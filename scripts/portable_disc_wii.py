"""Guarded Wii capture with redumper and source-based completion checks."""
# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

from portable_disc_identity import parse_header
from portable_disc_version import program_stamp


SOURCE_COMMIT = "642bdec05c83c52bbfb94f09a81e710118f96370"
REDUMPER_B767_SHA256 = "DA50272FB8681F4C42AFB178DB2DAF3FEB18A7143BABCD6BFB6EFBAE3D7DAF95"
STATE_PREFIX = 0x30000
RAW_SECTOR_BYTES = 2366
ISO_SECTOR_BYTES = 2048
SPACE_MARGIN = 64 * 1024 * 1024
STAGES = ("DUMP", "DUMP::EXTRA", "PROTECTION", "REFINE", "DVDKEY", "SPLIT", "HASH", "INFO")


def _safe_name(value):
    value = str(value)
    if not value or value in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,119}", value):
        raise ValueError("release_name must be a safe single path component")
    return value.rstrip(" .")


def _is_reparse(path):
    try:
        attrs = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attrs & 0x400)


def _nearest_existing(path):
    path = Path(path).absolute()
    missing = []
    while not path.exists():
        missing.append(path.name)
        parent = path.parent
        if parent == path:
            raise ValueError("path has no existing ancestor")
        path = parent
    return path, missing


def _overlap(left, right):
    a = Path(left).resolve(strict=False)
    b = Path(right).resolve(strict=False)
    return a == b or a in b.parents or b in a.parents


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def _fingerprint_matches_metadata(meta, platform="wii"):
    title_id = meta.get("title_id")
    disc_number = meta.get("disc_number")
    revision = meta.get("revision")
    if (not isinstance(title_id, str) or not re.fullmatch(r"[A-Za-z0-9]{6}", title_id)
            or not isinstance(disc_number, int) or isinstance(disc_number, bool) or disc_number < 1
            or not isinstance(revision, int) or isinstance(revision, bool) or not 0 <= revision <= 255):
        return False
    expected = f"{platform}:{title_id}:disc{disc_number}:rev{revision}"
    return meta.get("fingerprint") == expected


def _toc(meta):
    candidates = [meta.get("toc")]
    candidates.extend(x for x in meta.get("evidence", []) if isinstance(x, dict) and x.get("kind") == "toc")
    for item in candidates:
        if not isinstance(item, dict):
            continue
        rows = item.get("tracks")
        if item.get("status") == "complete" and isinstance(rows, list) and len(rows) == 1:
            row = rows[0]
            if isinstance(row, dict) and row.get("is_data") is True and row.get("lba") == 0:
                count = item.get("leadout_lba")
                if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                    return count
    return None


def _free_space(root):
    ancestor, _ = _nearest_existing(root)
    if not ancestor.is_dir():
        raise ValueError("capture ancestor is not a directory")
    if _is_reparse(ancestor):
        raise ValueError("capture ancestor is a reparse point")
    return shutil.disk_usage(ancestor).free


def _backup_state(folder, fingerprint):
    try:
        folder.lstat()
    except FileNotFoundError:
        return {"exists": False, "marker": None, "fingerprint_match": None}
    except OSError as exc:
        return {"exists": True, "marker": None, "fingerprint_match": False,
                "marker_error": f"candidate folder cannot be inspected: {exc}"}
    if _is_reparse(folder):
        return {"exists": True, "marker": None, "fingerprint_match": False,
                "marker_error": "candidate folder is a reparse point"}
    marker = folder / "backup_complete.json"
    result = {"exists": True, "marker": str(marker), "fingerprint_match": False}
    if not _is_reparse(marker) and marker.is_file():
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
            metadata = data.get("metadata")
            marker_fingerprint = metadata.get("fingerprint") if isinstance(metadata, dict) else None
            if marker_fingerprint is None:
                marker_fingerprint = data.get("fingerprint")
            result["fingerprint_match"] = marker_fingerprint == fingerprint
            result["marker_fingerprint"] = marker_fingerprint
        except (OSError, ValueError, TypeError):
            result["marker_error"] = "marker is unreadable or invalid JSON"
    return result


def _plan(cfg, meta, drive, capture_root, backup_root, release_name, platform):
    """Return a dry plan. This function does not create files or start redumper."""
    blockers = []
    try:
        name = _safe_name(release_name)
    except ValueError as exc:
        name = "blocked-release-name"
        blockers.append(str(exc))
    fingerprint = meta.get("fingerprint") if isinstance(meta, dict) else None
    if not isinstance(meta, dict) or meta.get("classification") != platform:
        blockers.append(f"metadata does not classify the source as {platform}")
    if platform == "gamecube" and (not isinstance(meta, dict) or str(meta.get("platform", "")).casefold() != "gamecube"):
        blockers.append("GameCube metadata platform does not match its classification")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        blockers.append("metadata has no logical-disc fingerprint")
    elif not _fingerprint_matches_metadata(meta, platform):
        blockers.append(f"{platform} fingerprint does not match its title ID, disc number, and revision fields")
    count = _toc(meta) if isinstance(meta, dict) else None
    if count is None:
        blockers.append("metadata lacks one complete data track at LBA 0 and a positive lead-out")
    if platform == "gamecube" and count != 712880:
        blockers.append("GameCube TOC must contain one complete data track with lead-out 712880")

    drive = str(drive)
    if not re.fullmatch(r"[A-Za-z]:", drive):
        blockers.append("drive must be a Windows drive letter such as E:")
    exe_value = cfg.get("tools", {}).get("redumper") if isinstance(cfg, dict) else None
    exe = Path(str(exe_value)).absolute() if exe_value else None
    if not exe or not exe.is_file() or exe.suffix.lower() != ".exe":
        blockers.append("configured redumper executable is missing or is not a Windows exe")
    elif _is_reparse(exe):
        blockers.append("redumper executable is a reparse point")
    else:
        try:
            if _sha256(exe) != REDUMPER_B767_SHA256:
                blockers.append("configured redumper executable does not match the verified b767 binary")
        except OSError as exc:
            blockers.append(f"redumper executable cannot be read: {exc}")

    capture = Path(capture_root).absolute()
    backup = Path(backup_root)
    if not str(capture_root).strip() or str(capture).startswith("\\\\"):
        blockers.append("capture root must be a configured local path")
    if str(backup_root).strip() == "":
        blockers.append("backup root is missing")
    try:
        ancestor, _ = _nearest_existing(capture)
        cursor = ancestor
        while True:
            if _is_reparse(cursor):
                blockers.append("capture path contains a reparse point")
                break
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        free = _free_space(capture)
    except (OSError, ValueError) as exc:
        free = 0
        blockers.append(f"capture root cannot be inspected: {exc}")

    required = ((count + STATE_PREFIX) * RAW_SECTOR_BYTES +
                (count + STATE_PREFIX) + count * ISO_SECTOR_BYTES + SPACE_MARGIN) if count else 0
    if free < required:
        blockers.append("capture volume has less free space than the raw, state, ISO, and safety margin")
    try:
        if _overlap(capture, backup):
            blockers.append("capture and backup roots overlap")
    except (OSError, ValueError):
        blockers.append("capture and backup roots cannot be compared safely")

    backup_folder = backup / name
    try:
        backup_ancestor, _ = _nearest_existing(backup_folder)
        if not backup_ancestor.is_dir():
            blockers.append("backup ancestor is not a directory")
        if _is_reparse(backup_ancestor):
            blockers.append("backup ancestor is a reparse point")
        # This is an access probe only. It does not enumerate the backup root or write to it.
        if not os.access(backup_ancestor, os.R_OK | os.X_OK):
            blockers.append("backup ancestor is not accessible")
    except (OSError, ValueError) as exc:
        blockers.append(f"backup root cannot be inspected: {exc}")
    backup_info = _backup_state(backup_folder, fingerprint)
    if backup_info["exists"]:
        blockers.append("candidate backup folder already exists; no inventory scan or overwrite is allowed")

    job_dir = capture / (name + "-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
    prefix = job_dir / name
    argv = [str(exe) if exe else "", "disc", f"--drive={drive}", f"--image-path={job_dir}",
            f"--image-name={name}", "--retries=100"]
    sectors = count or 0
    return {
        "ready": not blockers,
        "blockers": blockers,
        "job_dir": str(job_dir),
        "executable": str(exe) if exe else "",
        "drive": drive,
        "image_name": name,
        "iso_path": str(prefix) + ".iso",
        "state_path": str(prefix) + ".state",
        "raw_path": str(prefix) + ".sdram",
        "log_path": str(job_dir / "console.log"),
        "argv": argv,
        "expected_sectors": sectors,
        "expected_bytes": sectors * ISO_SECTOR_BYTES,
        "expected_state_bytes": sectors + STATE_PREFIX,
        "expected_raw_bytes": (sectors + STATE_PREFIX) * RAW_SECTOR_BYTES,
        "fingerprint": fingerprint,
        "classification": platform,
        "metadata": meta,
        "backup_root": str(backup),
        "backup_folder": name,
        "backup_state": backup_info,
        "required_space": required,
        "free_space": free,
        "source_commit": SOURCE_COMMIT,
        **program_stamp(),
    }


def plan_wii(cfg, meta, drive, capture_root, backup_root, release_name):
    """Return a dry Wii plan. Preserve the original Wii adapter API."""
    return _plan(cfg, meta, drive, capture_root, backup_root, release_name, "wii")


def plan_gamecube(cfg, meta, drive, capture_root, backup_root, release_name):
    """Return a dry GameCube plan for the shared fixed Nintendo DVD workflow."""
    return _plan(cfg, meta, drive, capture_root, backup_root, release_name, "gamecube")


def run_wii(plan):
    """Create an exclusive local job directory and run the fixed command in foreground."""
    if not plan.get("ready"):
        raise ValueError("Wii plan is blocked: " + "; ".join(plan.get("blockers", [])))
    name = _safe_name(plan.get("image_name", ""))
    drive = str(plan.get("drive", ""))
    if not re.fullmatch(r"[A-Za-z]:", drive):
        raise ValueError("plan drive must be a Windows drive letter")
    executable = Path(plan.get("executable", "")).absolute()
    if not executable.is_file() or executable.suffix.lower() != ".exe" or _is_reparse(executable):
        raise ValueError("plan redumper executable is missing or unsafe")
    if _sha256(executable) != REDUMPER_B767_SHA256:
        raise ValueError("plan redumper executable does not match the verified b767 binary")
    job = Path(plan["job_dir"])
    if job.exists() or _is_reparse(job):
        raise FileExistsError("planned exclusive job directory already exists")
    command = [str(executable), "disc", f"--drive={drive}", f"--image-path={job}",
               f"--image-name={name}", "--retries=100"]
    job.mkdir(parents=True, exist_ok=False)
    with (job / "job-manifest.json").open("x", encoding="utf-8") as manifest:
        json.dump({**plan, **program_stamp()}, manifest, indent=2, ensure_ascii=False)
        manifest.write("\n")
    log_path = job / "console.log"
    with log_path.open("xb") as log:
        process = subprocess.Popen(command, cwd=str(job), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, shell=False, bufsize=0)
        try:
            while True:
                chunk = process.stdout.read(8192)
                if chunk:
                    log.write(chunk)
                    log.flush()
                    try:
                        os.write(1, chunk)
                    except (OSError, UnicodeError):
                        pass
                elif process.poll() is not None:
                    break
            returncode = process.wait()
        except KeyboardInterrupt:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            raise
    if returncode:
        raise subprocess.CalledProcessError(returncode, command)
    return returncode


def run_nintendo_dvd(plan):
    """Run the fixed redumper DVD command shared by Wii and GameCube media."""
    if plan.get("classification") not in {"wii", "gamecube"}:
        raise ValueError("plan classification is not a supported Nintendo DVD platform")
    return run_wii(plan)


def _log_sectors(text, label):
    match = re.search(rf"sectors count \({label}\):\s*(\d+)", text, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _clean_dump_errors(text):
    dump = re.search(r"^\*\*\*\s+DUMP(?:\s+\(time check: \d+s\))?\s*$", text, re.MULTILINE)
    extra = re.search(r"^\*\*\*\s+DUMP::EXTRA(?:\s+\(time check: \d+s\))?\s*$", text, re.MULTILINE)
    if not dump or not extra or extra.start() <= dump.end():
        return False
    section = text[dump.end():extra.start()]
    blocks = list(re.finditer(r"media errors:\s*\n\s*SCSI:\s*(\d+)\s*\n\s*EDC:\s*(\d+)", section, re.IGNORECASE))
    return bool(blocks) and all(int(m.group(1)) == 0 and int(m.group(2)) == 0 for m in blocks)


def _verify(plan, platform):
    """Accept only exact source, image, state, log, and logical-header proof."""
    if not plan.get("ready"):
        raise ValueError(f"{platform} plan is blocked")
    if plan.get("classification") != platform or not isinstance(plan.get("metadata"), dict) or plan["metadata"].get("classification") != platform:
        raise ValueError("plan platform does not match source metadata")
    if platform == "gamecube" and (str(plan["metadata"].get("platform", "")).casefold() != "gamecube" or plan.get("expected_sectors") != 712880):
        raise ValueError("GameCube plan lacks the required platform and TOC geometry")
    if not _fingerprint_matches_metadata(plan["metadata"], platform) or plan["metadata"].get("fingerprint") != plan.get("fingerprint"):
        raise ValueError("plan fingerprint does not match source platform metadata")
    if not isinstance(plan.get("fingerprint"), str) or not plan["fingerprint"]:
        raise ValueError("plan has no source fingerprint")
    job = Path(plan["job_dir"])
    log_path = Path(plan["log_path"])
    iso_path, state_path, raw_path = (Path(plan[k]) for k in ("iso_path", "state_path", "raw_path"))
    for path in (job, log_path, iso_path, state_path, raw_path):
        if _is_reparse(path):
            raise ValueError("capture evidence contains a reparse point")
    log_bytes = log_path.read_bytes()
    log_text = log_bytes.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    marker = r"^\*\*\*\s+([A-Z:]+)(?:\s+\(time check: \d+s\))?\s*$"
    stages = [m.group(1).upper() for m in re.finditer(marker, log_text, re.MULTILINE)]
    expected_stages = list(STAGES)
    if stages != expected_stages + ["END"]:
        raise ValueError("redumper log lacks the complete ordered disc stages and END marker")
    capacity = _log_sectors(log_text, "READ_CAPACITY")
    physical = _log_sectors(log_text, "PHYSICAL")
    if capacity != plan["expected_sectors"] or physical != plan["expected_sectors"]:
        raise ValueError("log sector count does not match the complete source TOC")
    if not _clean_dump_errors(log_text):
        raise ValueError("DUMP stage lacks clean SCSI and EDC counters")
    if iso_path.stat().st_size != plan["expected_bytes"]:
        raise ValueError("ISO byte count does not match the source TOC")
    if state_path.stat().st_size != plan["expected_state_bytes"]:
        raise ValueError("state byte count does not match the source TOC and prefix")
    with state_path.open("rb") as state:
        state.seek(STATE_PREFIX)
        remaining = plan["expected_sectors"]
        while remaining:
            block = state.read(min(1024 * 1024, remaining))
            if not block or any(value != 4 for value in block):
                raise ValueError("a source sector does not have redumper SUCCESS state")
            remaining -= len(block)
    if raw_path.stat().st_size != plan["expected_raw_bytes"]:
        raise ValueError("raw SDRAM byte count does not match redumper source layout")
    with iso_path.open("rb") as image:
        header = parse_header(image.read(0x100))["metadata"]
    if header.get("classification") != platform or header.get("fingerprint") != plan["fingerprint"]:
        raise ValueError("captured ISO logical header does not match the planned fingerprint")
    proof = {
        "iso_path": str(iso_path),
        "completion_proof": "source stages, clean counters, sector counts, state bytes, exact files, and ISO header passed",
        "classification": platform,
        "fingerprint": plan["fingerprint"],
        "expected_sectors": plan["expected_sectors"],
        "iso_bytes": iso_path.stat().st_size,
        "state_bytes": state_path.stat().st_size,
        "raw_bytes": raw_path.stat().st_size,
        "state_success_value": 4,
        "read_capacity_sectors": capacity,
        "physical_sectors": physical,
        "dump_first_pass_media_errors_zero": True,
        "limitation": "Strict first-pass DUMP counters reject repaired sectors even when final state is SUCCESS.",
        "completed_stages": expected_stages + ["END"],
        "log_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "source_commit": SOURCE_COMMIT,
        "image_identity": header,
        **program_stamp(),
    }
    return proof


def verify_wii(plan):
    """Verify Wii output while preserving the original Wii adapter API."""
    return _verify(plan, "wii")


def verify_gamecube(plan):
    """Verify GameCube output with the shared Nintendo DVD completion rules."""
    return _verify(plan, "gamecube")
