"""Guarded, normal-mode DVD-Video preservation with redumper."""
# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
import uuid

import portable_disc_wii as wii
from portable_disc_version import program_stamp

SOURCE_COMMIT = wii.SOURCE_COMMIT
ISO_SECTOR_BYTES = 2048
MAX_IFO_BYTES = 1024 * 1024
MAX_DIRECTORY_ENTRIES = 256
MAX_READ_BUDGET = 1024 * 1024
_STAGE_MARKER = re.compile(r"^\*\*\*\s+([A-Z:]+)(?:\s+\(time check: \d+s\))?\s*$", re.MULTILINE)


def _toc(meta):
    candidates = [meta.get("toc")]
    candidates.extend(row for row in meta.get("evidence", [])
                      if isinstance(row, dict) and row.get("kind") == "toc")
    for toc in candidates:
        if not isinstance(toc, dict) or toc.get("status") != "complete":
            continue
        tracks = toc.get("tracks")
        if (isinstance(tracks, list) and len(tracks) == 1
                and isinstance(tracks[0], dict) and tracks[0].get("is_data") is True
                and tracks[0].get("lba") == 0):
            count = toc.get("leadout_lba")
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                return count
    return None


def preservation_name(meta):
    """Return a neutral path name from the measured volume label and structure hash."""
    fingerprint = meta.get("fingerprint") if isinstance(meta, dict) else None
    match = re.fullmatch(r"dvd-video-structure:([0-9a-fA-F]{64})", str(fingerprint or ""))
    if not match:
        raise ValueError("metadata lacks a DVD-Video structural fingerprint")
    label = meta.get("volume_label")
    label = re.sub(r"[^A-Za-z0-9._ -]+", "_", str(label or "DVD")).strip(" .") or "DVD"
    label = re.sub(r"\s+", "_", label)[:80].rstrip(" ._") or "DVD"
    return wii._safe_name(f"DVD.{label}.dvd-video.{match.group(1)[:12].upper()}")


def _safe_path_tree(path):
    cursor = Path(path).absolute()
    while True:
        if wii._is_reparse(cursor):
            raise ValueError("path contains a reparse point")
        if cursor.parent == cursor:
            return
        cursor = cursor.parent


def plan_dvd(cfg, meta, drive, capture_root, backup_root):
    """Build a dry DVD-Video plan. Do not create paths or start a capture."""
    blockers = []
    if not isinstance(meta, dict) or meta.get("classification") != "dvd_video":
        blockers.append("fresh metadata does not classify the source as DVD-Video")
    fingerprint = meta.get("fingerprint") if isinstance(meta, dict) else None
    if not re.fullmatch(r"dvd-video-structure:[0-9a-fA-F]{64}", str(fingerprint or "")):
        blockers.append("metadata lacks a DVD-Video structural fingerprint")
    sectors = _toc(meta) if isinstance(meta, dict) else None
    if sectors is None:
        blockers.append("metadata lacks a complete data TOC at LBA 0 with positive lead-out")
    try:
        name = preservation_name(meta)
    except (TypeError, ValueError) as exc:
        name = "blocked-dvd-video"
        blockers.append(str(exc))

    drive = str(drive)
    if not re.fullmatch(r"[A-Za-z]:", drive):
        blockers.append("drive must be a Windows drive letter such as E:")
    exe_value = cfg.get("tools", {}).get("redumper") if isinstance(cfg, dict) else None
    exe = Path(str(exe_value)).absolute() if exe_value else None
    if not exe or not exe.is_file() or exe.suffix.lower() != ".exe" or wii._is_reparse(exe):
        blockers.append("configured redumper executable is missing or unsafe")
    else:
        try:
            if wii._sha256(exe) != wii.REDUMPER_B767_SHA256:
                blockers.append("configured redumper executable does not match verified b767")
        except OSError as exc:
            blockers.append(f"configured redumper executable cannot be read: {exc}")

    capture = Path(capture_root).absolute()
    backup = Path(backup_root).absolute()
    if not str(capture_root).strip() or str(capture).startswith("\\\\"):
        blockers.append("capture root must be a local path")
    if not str(backup_root).strip():
        blockers.append("backup root is missing")
    try:
        _safe_path_tree(capture)
        ancestor, _ = wii._nearest_existing(capture)
        if not ancestor.is_dir():
            raise ValueError("capture ancestor is not a directory")
        free = shutil.disk_usage(ancestor).free
    except (OSError, ValueError) as exc:
        free = 0
        blockers.append(f"capture root cannot be inspected: {exc}")
    expected_bytes = sectors * ISO_SECTOR_BYTES if sectors else 0
    expected_state_bytes = sectors if sectors else 0
    required = expected_bytes + expected_state_bytes + wii.SPACE_MARGIN if sectors else 0
    if free < required:
        blockers.append("capture volume lacks space for ISO, state, and safety margin")
    try:
        if wii._overlap(capture, backup):
            blockers.append("capture and backup roots overlap")
    except (OSError, ValueError):
        blockers.append("capture and backup roots cannot be compared safely")

    backup_folder = backup / name
    try:
        _safe_path_tree(backup_folder)
        ancestor, _ = wii._nearest_existing(backup_folder)
        if not ancestor.is_dir():
            blockers.append("backup ancestor is not a directory")
        if not os.access(ancestor, os.R_OK | os.X_OK):
            blockers.append("backup ancestor is not readable")
        backup_folder.lstat()
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        blockers.append(f"backup root cannot be inspected: {exc}")
    else:
        blockers.append("canonical backup candidate already exists")

    job = capture / (name + "-" + time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
    prefix = job / name
    return {
        "ready": not blockers, "blockers": blockers, "job_dir": str(job),
        "executable": str(exe) if exe else "", "drive": drive, "image_name": name,
        "iso_path": str(prefix) + ".iso", "state_path": str(prefix) + ".state",
        "log_path": str(job / "console.log"), "backup_root": str(backup),
        "backup_folder": name, "expected_sectors": sectors or 0,
        "expected_bytes": expected_bytes, "expected_state_bytes": expected_state_bytes,
        "expected_geometry": {"sectors": sectors or 0, "bytes": expected_bytes,
                              "bytes_per_sector": ISO_SECTOR_BYTES, "lba_zero": 0},
        "fingerprint": fingerprint, "metadata": meta,
        "source_commit": SOURCE_COMMIT, **program_stamp(),
    }


def run_dvd(plan):
    """Run the existing fixed redumper disc command and lifecycle."""
    if plan.get("classification") not in (None, "dvd_video"):
        raise ValueError("DVD plan classification is invalid")
    return wii.run_wii(plan)


def _dual(data, offset, width, name):
    little = int.from_bytes(data[offset:offset + width], "little")
    big = int.from_bytes(data[offset + width:offset + width * 2], "big")
    if little != big:
        raise ValueError(f"ISO9660 {name} endian copies disagree")
    return little


def _record(data):
    if not data or data[0] < 34 or data[0] > len(data):
        raise ValueError("ISO9660 directory record has an invalid length")
    row = data[:data[0]]
    if len(row) < 34:
        raise ValueError("ISO9660 directory record is truncated")
    ext_attr = row[1]
    extent = _dual(row, 2, 4, "extent")
    length = _dual(row, 10, 4, "data length")
    flags, unit, gap, name_len = row[25], row[26], row[27], row[32]
    minimum = 33 + name_len + (1 if name_len % 2 == 0 else 0)
    if len(row) < minimum:
        raise ValueError("ISO9660 directory identifier length is invalid")
    if ext_attr or unit or gap or flags & 0x80:
        raise ValueError("ISO9660 extended, interleaved, or multi-extent records are unsupported")
    try:
        name = row[33:33 + name_len].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("ISO9660 filename is not ASCII") from exc
    return {"extent": extent, "length": length, "directory": bool(flags & 2), "name": name}


def _read_extent(stream, image_size, extent, length, budget):
    offset = extent * ISO_SECTOR_BYTES
    if length < 0 or offset > image_size or length > image_size - offset:
        raise ValueError("ISO9660 extent is outside the image")
    if length > budget[0]:
        raise ValueError("ISO9660 total read budget exceeded")
    budget[0] -= length
    stream.seek(offset)
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("ISO9660 extent read was short")
    return data


def _directory(stream, image_size, record, budget, total_entries):
    if not record["directory"]:
        raise ValueError("ISO9660 expected a directory record")
    raw = _read_extent(stream, image_size, record["extent"], record["length"], budget)
    rows, offset = [], 0
    while offset < len(raw):
        if raw[offset] == 0:
            offset = ((offset // ISO_SECTOR_BYTES) + 1) * ISO_SECTOR_BYTES
            continue
        row = _record(raw[offset:])
        rows.append(row)
        total_entries[0] += 1
        if total_entries[0] > MAX_DIRECTORY_ENTRIES:
            raise ValueError("ISO9660 directory exceeds 256 entries")
        offset += raw[offset]
    return rows


def _iso_fingerprint(path):
    with Path(path).open("rb") as image:
        image_size = Path(path).stat().st_size
        if image_size % ISO_SECTOR_BYTES:
            raise ValueError("ISO byte count is not a whole number of 2048-byte sectors")
        sectors = image_size // ISO_SECTOR_BYTES
        budget = [MAX_READ_BUDGET]
        pvd = None
        for sector in range(16, min(32, sectors)):
            descriptor = _read_extent(image, image_size, sector, ISO_SECTOR_BYTES, budget)
            if descriptor[1:6] == b"CD001" and descriptor[6] == 1 and descriptor[0] == 1:
                pvd = descriptor
                break
        if pvd is None:
            raise ValueError("ISO9660 primary volume descriptor was not found in sectors 16 through 31")
        if _dual(pvd, 128, 2, "logical block size") != ISO_SECTOR_BYTES:
            raise ValueError("ISO9660 logical block size is not 2048 bytes")
        root = _record(pvd[156:])
        if not root["directory"] or root["name"] != "\x00":
            raise ValueError("ISO9660 primary descriptor has an invalid root directory record")
        total_entries = [0]
        root_rows = _directory(image, image_size, root, budget, total_entries)
        root_names = {}
        for row in root_rows:
            if row["name"] in ("\x00", "\x01"):
                continue
            name = row["name"][:-2] if row["name"].endswith(";1") else row["name"]
            if name in (".", "..") or "/" in name or "\\" in name or name.casefold() in {key.casefold() for key in root_names}:
                raise ValueError("ISO9660 root contains a duplicate or unsafe path")
            root_names[name] = row
        video = next((row for name, row in root_names.items() if name.casefold() == "video_ts"), None)
        if not video or not video["directory"]:
            raise ValueError("ISO9660 root lacks VIDEO_TS directory")
        video_rows = _directory(image, image_size, video, budget, total_entries)
        listing, seen = [], set()
        ifo = None
        for row in video_rows:
            if row["name"] in ("\x00", "\x01"):
                continue
            name = row["name"][:-2] if row["name"].endswith(";1") else row["name"]
            if (not name or name in (".", "..") or "/" in name or "\\" in name
                or name.casefold() in seen):
                raise ValueError("VIDEO_TS contains a duplicate or unsafe path")
            seen.add(name.casefold())
            listing.append({"name": name, "size": None if row["directory"] else row["length"],
                            "directory": row["directory"]})
            if name.casefold() == "video_ts.ifo" and not row["directory"]:
                ifo = row
        if ifo is None:
            raise ValueError("VIDEO_TS lacks one VIDEO_TS.IFO file")
        if ifo["length"] > MAX_IFO_BYTES:
            raise ValueError("VIDEO_TS.IFO exceeds the 1 MiB fingerprint limit")
        ifo_bytes = _read_extent(image, image_size, ifo["extent"], ifo["length"], budget)
    if not ifo_bytes.startswith(b"DVDVIDEO-VMG"):
        raise ValueError("VIDEO_TS.IFO lacks the DVD video manager header")
    listing.sort(key=lambda item: item["name"].casefold())
    payload = json.dumps({"ifo_sha256": hashlib.sha256(ifo_bytes).hexdigest(), "entries": listing},
                         sort_keys=True, separators=(",", ":")).encode()
    return "dvd-video-structure:" + hashlib.sha256(payload).hexdigest(), listing, hashlib.sha256(ifo_bytes).hexdigest()


def verify_dvd(plan):
    """Verify ordered redumper completion, sector state, and DVD-Video structure."""
    if not plan.get("ready") or not isinstance(plan.get("metadata"), dict):
        raise ValueError("DVD plan is blocked or lacks source metadata")
    meta = plan["metadata"]
    if meta.get("classification") != "dvd_video" or meta.get("fingerprint") != plan.get("fingerprint"):
        raise ValueError("plan fingerprint does not match fresh DVD-Video metadata")
    if _toc(meta) != plan.get("expected_sectors") or not plan.get("expected_sectors"):
        raise ValueError("plan sector count does not match complete source TOC")
    job = Path(plan["job_dir"])
    log_path, iso_path, state_path = (Path(plan[key]) for key in ("log_path", "iso_path", "state_path"))
    for path in (job, log_path, iso_path, state_path):
        if wii._is_reparse(path):
            raise ValueError("capture evidence contains a reparse point")
    log_bytes = log_path.read_bytes()
    log_text = log_bytes.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    stages = [match.group(1).upper() for match in _STAGE_MARKER.finditer(log_text)]
    expected_stages = list(wii.STAGES) + ["END"]
    if stages != expected_stages:
        raise ValueError("redumper log lacks complete ordered stages and END")
    capacity = wii._log_sectors(log_text, "READ_CAPACITY")
    physical = wii._log_sectors(log_text, "PHYSICAL")
    if capacity != plan["expected_sectors"] or physical != plan["expected_sectors"]:
        raise ValueError("observed READ_CAPACITY or PHYSICAL count differs from source TOC")
    expected_bytes = plan["expected_sectors"] * ISO_SECTOR_BYTES
    expected_state_bytes = plan["expected_sectors"]
    if plan.get("expected_bytes") != expected_bytes or iso_path.stat().st_size != expected_bytes:
        raise ValueError("ISO byte count differs from source TOC")
    if plan.get("expected_state_bytes") != expected_state_bytes or state_path.stat().st_size != expected_state_bytes:
        raise ValueError("state byte count differs from normal ISO source TOC")
    with state_path.open("rb") as state:
        state.seek(0)
        remaining = plan["expected_sectors"]
        while remaining:
            block = state.read(min(1024 * 1024, remaining))
            if not block or any(value != 4 for value in block):
                raise ValueError("a source sector lacks redumper SUCCESS state")
            remaining -= len(block)
    fingerprint, listing, ifo_hash = _iso_fingerprint(iso_path)
    if fingerprint != plan["fingerprint"]:
        raise ValueError("captured ISO DVD-Video structure differs from fresh source fingerprint")
    dump = re.search(r"^\*\*\*\s+DUMP(?:\s+\(time check: \d+s\))?\s*$([\s\S]*?)^\*\*\*\s+DUMP::EXTRA", log_text, re.MULTILINE)
    errors = re.search(r"media errors:\s*\n\s*SCSI:\s*(\d+)\s*\n\s*EDC:\s*(\d+)", dump.group(1), re.IGNORECASE) if dump else None
    if errors is None:
        raise ValueError("DUMP stage lacks the first-pass SCSI and EDC summary")
    scsi = int(errors.group(1))
    edc = int(errors.group(2))
    if scsi != 0 or edc != 0:
        raise ValueError("first-pass DUMP SCSI and EDC counters must both be zero")
    css_match = re.search(r"\bCSS(?:\s+(?:protection|status))?\s*[:=]\s*(enabled|disabled|supported|unsupported|present|absent|detected|not detected)\b", log_text, re.IGNORECASE)
    return {
        "iso_path": str(iso_path), "completion_proof": "ordered stages, matching observed sectors, exact ISO and state sizes, SUCCESS states, and ISO structure passed",
        "complete": True, "verified": True, "matching": True,
        "classification": "dvd_video", "fingerprint": fingerprint,
        "expected_sectors": plan["expected_sectors"], "iso_bytes": expected_bytes,
        "state_bytes": expected_state_bytes, "state_success_value": 4,
        "read_capacity_sectors": capacity, "physical_sectors": physical,
        "read_state": "verified: every state byte from offset zero equals SUCCESS value 4",
        "image_geometry": "verified: normal ISO uses 2048-byte sectors from LBA zero",
        "iso_structure": "verified: captured VIDEO_TS listing and complete IFO hash match the fresh structural fingerprint",
        "first_pass_scsi_errors": scsi, "first_pass_edc_errors": edc,
        "repaired_sector_annotation": None,
        "physical_edc_validation": "not performed independently in normal ISO mode",
        "completed_stages": stages, "video_ts_entries": listing, "ifo_sha256": ifo_hash,
        "metadata_status": "metadata_pending", "unknowns": ["title", "year", "content_kind", "episode"],
        "jellyfin_playability": "not_assessed",
        "css": css_match.group(1).casefold() if css_match else "unknown",
        "css_log_evidence": css_match.group(0) if css_match else None,
        "log_sha256": hashlib.sha256(log_bytes).hexdigest(), "source_commit": SOURCE_COMMIT,
        **program_stamp(),
    }
