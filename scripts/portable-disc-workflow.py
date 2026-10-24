#!/usr/bin/env python3
"""Foreground optical-disc probe and verified manual backup ingest (Python 3.11+)."""
# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
from string import Formatter
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from portable_disc_identity import probe_raw, parse_header
from portable_disc_version import program_stamp, version_text

EVENTS = {"identified", "manual", "metadata", "ripping", "verifying", "backup_complete", "playable_pending", "local_complete", "completion_notice", "notification_delivery", "metadata_pending", "preservation_incomplete", "preservation_notice", "failed"}
RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def now():
    return datetime.now(timezone.utc).isoformat()


def safe_component(value):
    value = BAD_CHARS.sub("_", str(value)).strip(" .")[:120].rstrip(" .")
    stem = value.split(".", 1)[0].casefold()
    if not value or value in {".", ".."} or stem in RESERVED:
        raise ValueError(f"unsafe or empty path component: {value!r}")
    return value


def backup_root_for(cfg, classification, override=None):
    if override:
        return override
    platforms = cfg.get("platforms", {})
    if not isinstance(platforms, dict):
        raise ValueError("platforms must be a mapping by classification")
    entry = platforms.get(classification)
    if entry is not None and not isinstance(entry, dict):
        raise ValueError(f"platforms.{classification} must be an object")
    root = entry.get("backup_root") if isinstance(entry, dict) else None
    if root is not None and (not isinstance(root, str) or not root.strip()):
        raise ValueError(f"platforms.{classification}.backup_root must be a nonempty path")
    root = root or cfg.get("backup_root")
    if not root:
        raise ValueError(f"no NAS backup_root is configured for {classification}")
    return root


def load_config(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("config must be an object with version 1")
    return data


def event_path(cfg):
    return Path(cfg.get("state_file", "~/.local/state/ontherip/events.jsonl")).expanduser()


def read_events(path):
    rows = []
    if path.exists():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                row = json.loads(line)
                if row.get("event") in EVENTS:
                    rows.append(row)
            except (ValueError, AttributeError) as exc:
                raise ValueError(f"invalid state line {n}: {exc}") from exc
    return rows


def record(cfg, event, **fields):
    if event not in EVENTS:
        raise ValueError("invalid event")
    path = event_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"time": now(), "event": event, **fields, **program_stamp()}
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return row


@contextlib.contextmanager
def drive_lock(cfg, drive):
    if os.name == "nt": drive = str(drive).rstrip("\\/").upper()
    else:
        with contextlib.suppress(OSError): drive = str(Path(drive).resolve())
    lock_root = Path(cfg.get("lock_dir", "~/.local/state/ontherip/locks")).expanduser()
    lock_root.mkdir(parents=True, exist_ok=True)
    name = hashlib.sha256(str(drive).encode()).hexdigest()[:24] + ".lock"
    f = (lock_root / name).open("a+b")
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            if f.read(1) == b"":
                f.write(b"0"); f.flush()
            f.seek(0)
            try: msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc: raise RuntimeError("another workflow holds this drive lock") from exc
        else:
            import fcntl
            try: fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc: raise RuntimeError("another workflow holds this drive lock") from exc
        yield
    finally:
        if os.name == "nt":
            import msvcrt
            with contextlib.suppress(OSError):
                f.seek(0); msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            with contextlib.suppress(OSError): fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()


def windows_drives():
    script = "Get-CimInstance Win32_CDROMDrive | Select-Object Drive,PNPDeviceID,Name,MediaLoaded,VolumeName | ConvertTo-Json -Compress"
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, check=True, timeout=30)
    data = json.loads(result.stdout or "[]")
    if isinstance(data, dict): data = [data]
    return [{"drive": x.get("Drive"), "device": x.get("PNPDeviceID"), "name": x.get("Name"), "loaded": x.get("MediaLoaded"), "volume_label": x.get("VolumeName")} for x in data]


def linux_drives():
    found = []
    for p in Path("/sys/class/block").glob("sr*"):
        dev = Path("/dev") / p.name
        try:
            if (p / "device").exists():
                found.append({"drive": str(dev), "device": str((p / "device").resolve()), "name": (p / "device" / "vendor").read_text(errors="replace").strip() if (p / "device" / "vendor").exists() else "optical", "loaded": None})
        except OSError: continue
    return found


def list_drives():
    if os.name == "nt": return windows_drives()
    if sys.platform.startswith("linux"):
        return linux_drives()
    return []


def mounted_linux(dev):
    if not sys.platform.startswith("linux"): return None
    try:
        major_minor = os.stat(dev).st_rdev
        devnum = f"{os.major(major_minor)}:{os.minor(major_minor)}"
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            parts = line.split()
            if parts[2] == devnum:
                return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), parts[4])
    except OSError as exc:
        raise ValueError(f"cannot establish mount state: {dev}") from exc
    return None


def parse_sfo(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024: raise ValueError("SFO exceeds the supported size")
    if len(raw) < 20 or raw[:4] != b"\x00PSF": raise ValueError("not a PS3 PARAM.SFO")
    key_off, data_off, count = struct.unpack_from("<III", raw, 8)
    if count > 4096 or key_off > len(raw) or data_off > len(raw): raise ValueError("invalid SFO offsets/count")
    out = {}
    for i in range(count):
        pos = 20 + i * 16
        if pos + 16 > len(raw): raise ValueError("truncated SFO index")
        key_i, fmt, length, maxlen, data_i = struct.unpack_from("<HHIII", raw, pos)
        ks, ds = key_off + key_i, data_off + data_i
        ke = raw.find(b"\0", ks)
        if ks >= data_off or ke < 0 or ke >= data_off or ds + length > len(raw): raise ValueError("invalid SFO entry")
        key = raw[ks:ke].decode("ascii", "replace")
        if fmt in (0x0204, 0x0004): out[key] = raw[ds:ds+length].split(b"\0", 1)[0].decode("utf-8", "replace").strip()
    return {k: out[k] for k in ("TITLE", "TITLE_ID") if k in out}


def probe_drive(drive):
    if os.name == "nt": drive = str(drive).rstrip("\\/").upper()
    result = next((x for x in list_drives() if str(x["drive"]).casefold() == str(drive).casefold()), None)
    if not result: raise ValueError(f"optical drive not found: {drive}")
    root = Path(drive)
    if os.name == "nt":
        root = Path(str(drive) + "\\")
    elif sys.platform.startswith("linux"):
        root = Path(mounted_linux(drive) or "/__unmounted_disc__")
    metadata = {"drive": result["drive"], "device": result["device"], "drive_name": result["name"], "media_loaded": result.get("loaded"), "volume_label": result.get("volume_label"), "title": None, "title_id": None, "identity_scope": "drive only; disc identity unknown", "classification": "unknown", "mounted_root": None, "evidence": [], "inquiry_errors": []}
    mounted_identity = {}
    mounted_attempted = False
    mounted_conflict = False
    def read_mounted():
        nonlocal mounted_attempted, mounted_conflict
        mounted_attempted = True
        try:
            if root.exists():
                metadata["mounted_root"] = str(root)
                sfo = root / "PS3_GAME" / "PARAM.SFO"
                if sfo.is_file():
                    values = parse_sfo(sfo)
                    metadata.update({"title": values.get("TITLE"), "title_id": values.get("TITLE_ID")})
                    if re.fullmatch(r"[A-Z]{4}[0-9]{5}", values.get("TITLE_ID", "").upper()):
                        metadata.update({"classification": "ps3", "platform": "PS3", "fingerprint": "ps3:" + values["TITLE_ID"].upper(), "identity_scope": "PS3 software serial; identifies logical title, not physical disc"})
                        mounted_identity.update({"classification": "ps3", "platform": "PS3", "fingerprint": "ps3:" + values["TITLE_ID"].upper(), "identity_scope": "PS3 software serial; identifies logical title, not physical disc"})
                        metadata["evidence"].append({"source": "PS3_GAME/PARAM.SFO", "kind": "embedded software serial"})
                recognized = []
                for relative, magic, classification in (("VIDEO_TS/VIDEO_TS.IFO", b"DVDVIDEO-VMG", "dvd_video"), ("BDMV/index.bdmv", b"INDX", "bluray_video")):
                    path = root / relative
                    if path.is_file():
                        with path.open("rb") as stream: header = stream.read(12)
                        if header.startswith(magic):
                            recognized.append((relative, classification))
                if len(recognized) > 1:
                    mounted_conflict = True
                    raise ValueError("conflicting mounted DVD and Blu-ray video structures")
                if recognized:
                    relative, classification = recognized[0]
                    if mounted_identity.get("classification") and mounted_identity["classification"] != classification:
                        mounted_conflict = True
                        raise ValueError("conflicting mounted PS3 and video structures")
                    mounted_identity.update({"classification": classification, "identity_scope": "mounted video structure; title and physical disc unknown"})
                    metadata["evidence"].append({"source": relative, "kind": "video structure header"})
                    if classification == "dvd_video":
                        mounted_identity.update(dvd_video_fingerprint(root))
                        metadata["evidence"].append({"kind": "structural_fingerprint", **mounted_identity["fingerprint_evidence"]})
                        mounted_identity["fingerprint"] = mounted_identity.pop("fingerprint_value")
                        mounted_identity.pop("fingerprint_evidence")
        except (OSError, ValueError) as exc:
            metadata["inquiry_errors"].append({"operation": "mounted filesystem metadata", "winerror": getattr(exc, "winerror", None), "errno": getattr(exc, "errno", None), "error": str(exc)})
        return bool(metadata.get("fingerprint"))
    # Filesystem access is optional: opaque game media and audio CDs need device inquiries.
    if result.get("loaded") is not False:
        raw = probe_raw(str(result["drive"]), mounted_reader=read_mounted)
        if not mounted_attempted: read_mounted()
        identity = raw.get("metadata", {})
        raw_classification = identity.get("classification")
        mounted_classification = mounted_identity.get("classification")
        generic_filesystems = {"iso9660", "udf"}
        identity_conflict = mounted_conflict or bool(mounted_classification and raw_classification and raw_classification not in generic_filesystems and raw_classification != mounted_classification)
        if identity_conflict:
            conflict_sources = {"mounted": mounted_classification or ["dvd_video", "bluray_video"], "raw": raw_classification}
            metadata["classification"] = "unknown"
            metadata["identity_scope"] = "conflicting evidence; identity discarded"
            for key in ("fingerprint", "title", "title_id", "platform", "disc_number", "revision"):
                metadata.pop(key, None)
            metadata["evidence"].append({"kind": "identity_conflict", **conflict_sources})
        elif mounted_classification:
            metadata.update(mounted_identity)
        else:
            for key in ("classification", "title", "title_id", "platform", "fingerprint", "identity_scope", "disc_number", "revision", "musicbrainz_disc_id"):
                if identity.get(key) is not None: metadata[key] = identity[key]
        metadata["evidence"].extend(raw.get("evidence", []))
        metadata["inquiry_errors"].extend(raw.get("errors", []))
        if "disc_change_count" in raw: metadata["disc_change_count"] = raw["disc_change_count"]
        metadata["identity_consistency"] = raw.get("identity_consistency", "unavailable")
        if identity_conflict:
            metadata["identity_consistency"] = "conflicting mounted and raw identity; classification discarded"
        elif metadata["identity_consistency"] == "changed":
            for key in ("title", "title_id", "platform", "fingerprint", "disc_number", "revision"):
                metadata.pop(key, None)
            metadata["classification"] = "unknown"
            metadata["identity_scope"] = "media changed during the probe; identity discarded"
            for item in metadata["evidence"]: item["invalidated_by_media_change"] = True
    metadata["probe_status"] = "structure_identified_title_unknown" if metadata.get("classification") == "dvd_video" and metadata.get("fingerprint") else ("identified" if metadata.get("fingerprint") else ("no_media" if result.get("loaded") is False else "incomplete"))
    metadata["swap_observation"] = "OS media-change counter available" if metadata.get("disc_change_count") is not None else "unknown-to-unknown swaps cannot be distinguished without an observed presence change"
    metadata["unknown_fields"] = [key for key in ("title", "title_id", "classification", "region", "languages", "edition", "barcode", "release_date") if not metadata.get(key) or metadata[key] == "unknown"]
    return {**metadata, **program_stamp()}


def dvd_video_fingerprint(root):
    """Hash bounded DVD structure evidence, not a unique physical-disc identity."""
    video_ts = Path(root) / "VIDEO_TS"
    entries = []
    for item in video_ts.iterdir():
        entries.append(item)
        if len(entries) > 256: raise ValueError("VIDEO_TS contains more than 256 top-level entries")
    entries.sort(key=lambda item: item.name.casefold())
    listing = []
    for item in entries:
        if item.is_symlink(): raise ValueError("VIDEO_TS structure contains a symlink")
        listing.append({"name": item.name, "size": item.stat().st_size if item.is_file() else None, "directory": item.is_dir()})
    if len(listing) != len(entries): raise ValueError("VIDEO_TS structure listing is incomplete")
    info = video_ts / "VIDEO_TS.IFO"
    with info.open("rb") as stream: raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024: raise ValueError("VIDEO_TS.IFO exceeds the 1 MiB fingerprint limit")
    if not raw.startswith(b"DVDVIDEO-VMG"): raise ValueError("VIDEO_TS.IFO no longer has the verified DVD video header")
    payload = json.dumps({"ifo_sha256": hashlib.sha256(raw).hexdigest(), "entries": listing}, sort_keys=True, separators=(",", ":")).encode()
    value = "dvd-video-structure:" + hashlib.sha256(payload).hexdigest()
    evidence = {"method": "sha256 of VIDEO_TS.IFO bytes and bounded top-level VIDEO_TS names/sizes", "limits": {"ifo_bytes": 1048576, "top_level_entries": 256}, "meaning": "structural comparison only; not unique physical-disc or full movie identity"}
    dvd_text = {"pointer_status": "unavailable", "reason": "VMGI header is shorter than 216 bytes"}
    if len(raw) >= 216:
        sector = struct.unpack_from(">I", raw, 0xD4)[0]
        dvd_text = {"pointer_status": "zero" if sector == 0 else "nonzero", "sector": sector,
                    "byte_offset": sector * 2048,
                    "meaning": "DVD-TEXT table declaration only; no release title, year, or episode decoded"}
    evidence["dvd_text"] = dvd_text
    return {"fingerprint_value": value, "fingerprint_evidence": evidence}


def is_suppressed(cfg, fingerprint):
    if fingerprint in set(cfg.get("suppressed_fingerprints", [])):
        return True
    blocked = False
    for row in read_events(event_path(cfg)):
        if row.get("fingerprint") != fingerprint:
            continue
        if row.get("event") in {"backup_complete", "local_complete"}:
            return True
        if row.get("action") == "explicit-retry":
            blocked = False
        elif row.get("event") in {"failed", "ripping"}:
            blocked = True
    return blocked


def inspect(cfg, drive):
    m = probe_drive(drive)
    fp = m.get("fingerprint")
    m["decision"] = "suppressed" if fp and is_suppressed(cfg, fp) else ("structure identified; release identity incomplete" if m.get("classification") == "dvd_video" else ("identification incomplete; no capture started" if not fp else "identified; no capture started"))
    m["metadata_handler"] = "makemkv_info" if m.get("classification") == "dvd_video" else None
    m["capture_handler"] = {"ps3": "ps3_gui", "wii": "redumper_wii", "gamecube": "redumper_gamecube", "dvd_video": "redumper_dvd_preserve"}.get(m.get("classification")) if fp else None
    if m["capture_handler"] is None:
        m["capture_blocker"] = "no matching capture adapter and format-specific completion check are implemented"
    if m.get("classification") == "dvd_video":
        m["title"] = None
        m["release_year"] = None
        m["probe_status"] = "structure_identified_title_unknown"
        m.pop("capture_blocker", None)
    return m


def _dvd_summary(result):
    robot = result.get("robot", {})
    warnings = robot.get("source_integrity_warnings", [])
    samples = []
    for warning in warnings[:3]:
        samples.append({"file": warning.get("file"), "offset": warning.get("offset")})
    return {
        "status": result.get("probe_status"), "native_exit_code": result.get("exit_code"),
        "title_count": robot.get("title_count"), "metadata_only": True,
        "title": None, "year": None, "content_kind": None,
        "unknowns": ["title", "year", "content_kind", "episode"],
        "post_probe_consistency": result.get("post_probe_consistency"),
        "dvd_text": next((item.get("dvd_text") for item in result.get("metadata", {}).get("evidence", [])
                          if item.get("kind") == "structural_fingerprint"), None),
        "message_counts": robot.get("message_counts", {}),
        "source_integrity_warning_count": len(warnings), "warning_samples": samples,
        "metadata_diagnostics": list(dict.fromkeys(result.get("blockers", []))),
        "preservation_blockers": list(result.get("preservation_blockers", [])),
        "evidence_directory": result.get("evidence_directory"),
        "report_path": result.get("report_path"),
        "result_path": result.get("result_path"),
        "observation_path": result.get("post_probe_receipt"),
    }


def _dvd_probe_summary(metadata):
    return {"status": "probe_only", "drive": metadata.get("drive"),
            "classification": "dvd_video", "fingerprint": metadata.get("fingerprint"),
            "title": None, "year": None, "content_kind": None,
            "dvd_text": next((item.get("dvd_text") for item in metadata.get("evidence", [])
                              if item.get("kind") == "structural_fingerprint"), None),
            "metadata_query": "not run; optional metadata-only dvd-info command",
            "metadata_status": "title/year/content/episode unknown; preservation remains available",
            "preservation_blockers": []}


def run_vlc_info(cfg, report_json=False):
    if os.name != "nt": raise ValueError("vlc-info requires the enabled Windows profile")
    from portable_disc_video import inspect_vlc
    configured_root = cfg.get("inspection_root")
    if not configured_root:
        raise ValueError("configure inspection_root as an absolute local Windows path first")
    base = Path(configured_root).expanduser().absolute()
    if not base.is_absolute() or str(base).startswith("\\\\") or not base.drive:
        raise ValueError("VLC inspection evidence must use an absolute local Windows path")
    import ctypes
    if ctypes.windll.kernel32.GetDriveTypeW(base.drive + "\\") not in {2, 3}:
        raise ValueError("VLC inspection evidence must use a local removable or fixed drive")
    reject_links(base)
    if not base.is_dir():
        raise ValueError("VLC inspection root must already exist")
    evidence_dir = base / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex)
    report = inspect_vlc(cfg, evidence_dir)
    report_path = str(evidence_dir / "report.json")
    report["report_path"] = report_path
    summary = {
        "status": report.get("status"), "vlc_version": report.get("vlc_version", "unknown"),
        "executable": report.get("executable"), "executable_bytes": report.get("executable_bytes"),
        "executable_sha256": report.get("executable_sha256"),
        "queries": {name: {"returncode": item.get("returncode"), "error": item.get("error"),
                            "stdout": item.get("stdout", {}).get("path"), "stderr": item.get("stderr", {}).get("path")}
                    for name, item in report.get("queries", {}).items()},
        "options": report.get("options", {}), "metadata_only": True,
        "help_scope": report.get("help_scope"), "error": report.get("error"),
        "module_availability_evidence": report.get("module_availability_evidence", {}),
        "menu_opened": False, "capture_started": False,
        "evidence_directory": str(evidence_dir), "report_path": report_path,
    }
    record(cfg, "metadata", action="vlc-capabilities", report=summary)
    print(json.dumps(report if report_json else summary, separators=(",", ":"), ensure_ascii=False))
    return 0 if report.get("status") == "complete" else 2


def run_dvd_info(cfg, drive, metadata, report_json=False):
    if os.name != "nt": raise ValueError("dvd-info requires the enabled Windows profile")
    if metadata.get("classification") != "dvd_video" or not metadata.get("fingerprint"):
        raise ValueError("dvd-info requires a stable, recognized DVD video structure")
    if metadata.get("identity_consistency") == "changed":
        raise ValueError("DVD media changed during the pre-query probe; metadata inspection refused")
    from portable_disc_video import inspect_dvd
    configured_root = cfg.get("inspection_root")
    if not configured_root:
        raise ValueError("configure inspection_root as an absolute local Windows path first")
    root = Path(configured_root).expanduser().absolute()
    if not root.is_absolute() or str(root).startswith("\\\\") or not root.drive:
        raise ValueError("DVD inspection evidence must use an absolute local Windows path")
    if root.drive.casefold() == str(drive).rstrip("\\/").casefold():
        raise ValueError("DVD inspection evidence cannot use the optical drive")
    import ctypes
    if ctypes.windll.kernel32.GetDriveTypeW(root.drive + "\\") not in {2, 3}:
        raise ValueError("DVD inspection evidence must use a local removable or fixed drive")
    reject_links(root)
    evidence_dir = root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex)
    report = inspect_dvd(cfg, drive, metadata, evidence_dir)
    post_error = None
    try:
        after = inspect(cfg, drive)
    except Exception as exc:
        after = {}
        post_error = f"{type(exc).__name__}: {exc}"
    before_count, after_count = metadata.get("disc_change_count"), after.get("disc_change_count")
    paired_counters = before_count is not None and after_count is not None
    counter_changed = paired_counters and before_count != after_count
    stable = (post_error is None and after.get("classification") == "dvd_video"
              and after.get("identity_consistency") != "changed"
              and after.get("fingerprint") == metadata.get("fingerprint") and not counter_changed)
    consistency = ("post_probe_error" if post_error else
                   ("changed_or_mismatched" if not stable else
                    ("matching_structures_and_counter" if paired_counters else
                     "matching_structures_counter_unavailable_or_partial")))
    query_ok = report.get("status") == "metadata_collected"
    result = {**report, "metadata_only": True, "capture_started": False, "capture_handler": None,
              "metadata_handler": "makemkv_info", "probe_status": "metadata_query_complete_title_unknown" if query_ok and stable else ("metadata_query_stale" if not stable else "metadata_query_failed"),
              "metadata_diagnostics": list(report.get("blockers", [])), "preservation_blockers": [],
              "fingerprint": metadata["fingerprint"], "evidence_directory": str(evidence_dir),
              "post_probe_consistency": consistency,
              "identity_limit": "structural comparison only; not a unique physical disc or verified release identity"}
    receipt = {"created_utc": now(), "status": result["probe_status"], "before_fingerprint": metadata.get("fingerprint"),
               "after_fingerprint": after.get("fingerprint"), "before_disc_change_count": metadata.get("disc_change_count"),
               "after_disc_change_count": after.get("disc_change_count"), "after_identity_consistency": after.get("identity_consistency"),
               "post_probe_error": post_error, "consistency_basis": consistency,
               "makemkv_report_status": report.get("status"), "meaning": "post-query structural consistency receipt; not a unique physical disc or verified release identity"}
    receipt_path = evidence_dir / "observation.json"
    with receipt_path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    result["post_probe_receipt"] = str(receipt_path)
    result["report_path"] = str(evidence_dir / "report.json")
    result["result_path"] = str(evidence_dir / "result.json")
    with (evidence_dir / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    summary = _dvd_summary(result)
    event_report = {"drive": drive, "fingerprint": metadata["fingerprint"],
                    "status": result.get("probe_status"),
                    "warning_counts": report.get("robot", {}).get("message_counts", {}),
                    "source_integrity_warning_count": len(report.get("robot", {}).get("source_integrity_warnings", [])),
                    "evidence_directory": str(evidence_dir), "report_path": result["report_path"],
                    "result_path": result["result_path"], "observation_path": str(receipt_path),
                    "blockers": result.get("blockers", [])}
    record(cfg, "metadata", drive=drive, fingerprint=metadata["fingerprint"], report=event_report)
    print(json.dumps(result, indent=2, ensure_ascii=False) if report_json
          else json.dumps(summary, separators=(",", ":"), ensure_ascii=False))
    if post_error:
        raise ValueError("DVD post-query probe failed; discard this inspection result: " + post_error)
    if not stable:
        raise ValueError("DVD media changed during metadata inspection; discard this inspection result")
    if not query_ok:
        raise ValueError("MakeMKV info did not complete a valid metadata query; see the saved report")
    return result


def show_probe(cfg, drive, log=False, metadata=None):
    m = metadata if metadata is not None else inspect(cfg, drive)
    print(json.dumps(m, indent=2, ensure_ascii=False))
    if log:
        record(cfg, "identified" if m.get("fingerprint") else "manual", fingerprint=m.get("fingerprint"), drive=m["drive"], metadata=m)


def reject_links(path):
    path = Path(path).absolute()
    for part in [path, *path.parents]:
        if part.is_symlink(): raise ValueError(f"symlink rejected: {part}")
        try: attributes = getattr(part.lstat(), "st_file_attributes", 0)
        except FileNotFoundError: continue
        if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ValueError(f"reparse point rejected: {part}")


def safe_tree(root):
    root = Path(root).absolute()
    reject_links(root)
    if root.is_symlink() or not root.exists(): raise ValueError("source does not exist or is a symlink")
    files = []
    paths = [root] if root.is_file() else [root, *root.rglob("*")]
    seen = set()
    for p in paths:
        if p.is_symlink(): raise ValueError(f"symlink rejected: {p}")
        if getattr(p.lstat(), "st_file_attributes", 0) & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0x400): raise ValueError(f"reparse point rejected: {p}")
        if p.is_file():
            rel = p.name if root.is_file() else p.relative_to(root).as_posix()
            if any(part in {".", ".."} or part.endswith((".", " ")) or part.split(".", 1)[0].casefold() in RESERVED or BAD_CHARS.search(part) for part in PurePosixPath(rel).parts): raise ValueError(f"unsafe source name: {rel}")
            if rel.casefold() in seen: raise ValueError(f"case-colliding source name: {rel}")
            seen.add(rel.casefold())
            files.append((rel, p))
    if not files: raise ValueError("source has no files")
    return root, sorted(files)


def signatures(path):
    with Path(path).open("rb") as f:
        head = f.read(64 * 1024)
    marks = []
    if head.startswith(b"fLaC"): marks.append("FLAC")
    if head.startswith(b"\x1aE\xdf\xa3"): marks.append("EBML header")
    with Path(path).open("rb") as f:
        f.seek(16 * 2048)
        probe = f.read(16 * 2048)
    if any(probe[i+1:i+7] == b"CD001\x01" for i in range(0, len(probe), 2048)):
        marks.append("ISO-9660 (CD001)")
    if any(probe[i+1:i+6] in {b"NSR02", b"NSR03"} for i in range(0, len(probe), 2048)): marks.append("UDF header")
    return marks


def release_name(meta, cfg=None):
    template = (cfg or {}).get("naming_template", "{title}.{platform}.{title_id}.Disc{disc_number}.Rev{revision}")
    if not isinstance(template, str) or len(template) > 512:
        raise ValueError("naming_template must be a string of at most 512 characters")
    allowed = {"title", "platform", "title_id", "disc_number", "revision", "region", "edition", "barcode"}
    for _, field, specification, conversion in Formatter().parse(template):
        if field is not None:
            if field not in allowed or specification or conversion:
                raise ValueError("naming_template supports plain known metadata fields only")
    parts = []
    for segment in template.split("."):
        fields = list(Formatter().parse(segment))
        if any(field is not None and meta.get(field) is None for _, field, _, _ in fields):
            continue
        parts.append("".join(literal + (str(meta[field]) if field is not None else "") for literal, field, _, _ in fields))
    tokens = [x for x in re.split(r"[^A-Za-z0-9]+", ".".join(parts)) if x]
    if not tokens: return "Disc.Manual"
    return ".".join(tokens)


def hash_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""): h.update(b)
    return h.hexdigest()


def nonoverlap(a, b):
    reject_links(a)
    reject_links(b)
    a, b = Path(a).resolve(), Path(b).resolve()
    if a == b or a in b.parents or b in a.parents: raise ValueError("source and destination must not overlap")


def copy_tree(files, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=False)
    for rel, src in files:
        target = dest.joinpath(*PurePosixPath(rel).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb") as out, src.open("rb") as inp: shutil.copyfileobj(inp, out)


def file_records(files):
    return [{"path": rel, "bytes": p.stat().st_size, "sha256": hash_file(p), "signatures": signatures(p)} for rel, p in files]


def ingest(cfg, args):
    if not args.confirmed_complete or not args.metadata: raise ValueError("ingest requires --confirmed-complete and --metadata JSON")
    meta = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    if not isinstance(meta, dict) or not meta.get("classification"): raise ValueError("metadata must include a truthful classification")
    backup_root = backup_root_for(cfg, meta["classification"], getattr(args, "backup_root", None))
    src, files = safe_tree(args.source)
    reject_links(backup_root)
    base = Path(backup_root).expanduser().resolve()
    nonoverlap(src, base)
    backup_folder = safe_component(args.backup_folder or release_name(meta, cfg))
    if args.local_root:
        reject_links(args.local_root)
        local_preflight = Path(args.local_root).resolve()
        nonoverlap(src, local_preflight)
        nonoverlap(base, local_preflight)
    base.mkdir(parents=True, exist_ok=True)
    final = base / backup_folder
    record(cfg, "verifying", source=str(src), destination=str(final), metadata=meta)
    try:
        source_records = file_records(files)
        final.mkdir(exist_ok=False)
        data_dir = final / "data"
        copy_tree(files, data_dir)
        copied = safe_tree(data_dir)[1]
        if sorted(x[0] for x in copied) != sorted(x[0] for x in files): raise ValueError("destination file list differs")
        reread = file_records(copied)
        if reread != source_records: raise ValueError("final destination reread differs")
        if file_records(safe_tree(src)[1]) != source_records: raise ValueError("source changed during ingest")
        manifest = {"version": 1, "created": now(), "metadata": meta, "source": str(src), "records": source_records, **program_stamp()}
        marker_final = final / "backup_complete.json"
        with marker_final.open("x", encoding="utf-8") as f: json.dump(manifest, f, indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
        record(cfg, "backup_complete", fingerprint=meta.get("fingerprint"), destination=str(final), files=len(files), records=source_records)
        if args.local_root:
            local_base = local_preflight
            local_base.mkdir(parents=True, exist_ok=True)
            local_dest = local_base / backup_folder
            local_dest.mkdir(exist_ok=False)
            copy_tree(files, local_dest / "data")
            reread_local = file_records(safe_tree(local_dest / "data")[1])
            if reread_local != source_records: raise ValueError("local destination reread differs")
            if file_records(safe_tree(src)[1]) != source_records: raise ValueError("source changed during local copy")
            with (local_dest / "local_complete.json").open("x", encoding="utf-8") as f:
                json.dump({"records": reread_local, "metadata": meta, **program_stamp()}, f, indent=2)
                f.write("\n"); f.flush(); os.fsync(f.fileno())
            record(cfg, "local_complete", fingerprint=meta.get("fingerprint"), destination=str(local_dest), records=reread_local)
        return str(final)
    except Exception as exc:
        record(cfg, "failed", fingerprint=meta.get("fingerprint"), source=str(src), destination=str(final), error=str(exc))
        raise


def redumper_command(cfg, drive, metadata_path):
    if not sys.platform.startswith("linux"): raise ValueError("redumper dispatch is Linux-only")
    if not re.fullmatch(r"/dev/sg[0-9]+", str(drive)): raise ValueError("redumper requires an explicit /dev/sgN device")
    meta = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
    if meta.get("classification") not in {"audio_cd", "data_cd"} or meta.get("manual_confirmed") is not True:
        raise ValueError("redumper requires per-run metadata classified audio_cd or data_cd and manual_confirmed=true")
    dev = Path(drive)
    if not dev.exists(): raise ValueError("configured sg device does not exist")
    sg_device = (Path("/sys/class/scsi_generic") / dev.name / "device").resolve(strict=True)
    block_device = None
    for block in Path("/sys/class/block").glob("sr*"):
        try:
            if (block / "device").resolve() == sg_device:
                block_device = "/dev/" + block.name
                if mounted_linux(block_device): raise ValueError("optical block device is mounted; unmount it before redumper")
        except OSError: continue
    if block_device is None: raise ValueError("cannot map the sg device to an optical block device")
    exe = cfg.get("tools", {}).get("redumper")
    if not exe or not Path(exe).is_file(): raise ValueError("configure the redumper executable path first")
    outroot = Path(cfg.get("capture_root", ""))
    if not str(cfg.get("capture_root", "")).strip(): raise ValueError("configure capture_root first")
    outroot.mkdir(parents=True, exist_ok=True)
    image = safe_component(release_name(meta, cfg))
    outdir = outroot / (image + "-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    outdir.mkdir(exist_ok=False)
    return [str(Path(exe).resolve()), "disc", f"--drive={drive}", f"--image-path={outdir}", f"--image-name={image}", "--retries=100"], meta, outdir


def dispatch_ps3(cfg, drive, meta):
    fresh = inspect(cfg, drive)
    if (fresh.get("classification") != "ps3" or not fresh.get("fingerprint")
            or fresh.get("fingerprint") != meta.get("fingerprint") or fresh.get("decision") == "suppressed"
            or fresh.get("identity_consistency") != "stable_counter"):
        raise ValueError("media identity changed, is incomplete, or is completed; no capture started")
    gui = cfg.get("tools", {}).get("ps3_gui")
    if not gui or not Path(gui).is_file(): raise ValueError("configure a known PS3 GUI executable path first")
    if os.name == "nt" and Path(gui).suffix.lower() != ".exe":
        raise ValueError("the Windows PS3 tool path must name an exe")
    record(cfg, "ripping", fingerprint=meta.get("fingerprint"), drive=drive, mode="PS3 GUI launch; manual completion required")
    try:
        result = subprocess.run([str(Path(gui).resolve())], shell=False, check=False)
        if result.returncode: raise RuntimeError(f"PS3 GUI exited with status {result.returncode}")
    except (OSError, RuntimeError) as exc:
        record(cfg, "failed", fingerprint=meta.get("fingerprint"), drive=drive, error=str(exc)); raise
    print("Configured PS3 GUI launched. Confirm completion manually, then run ingest.")


def nintendo_plan(cfg, drive, meta, args):
    from portable_disc_wii import plan_gamecube, plan_wii
    capture_root = args.capture_root or cfg.get("capture_root")
    try:
        backup_root = backup_root_for(cfg, meta.get("classification"), args.backup_root)
    except ValueError as exc:
        return {"ready": False, "blockers": [str(exc)]}
    if not capture_root or not backup_root:
        return {"ready": False, "blockers": ["configure capture_root and backup_root or pass their command options"]}
    capture_root, backup_root = Path(capture_root).expanduser(), Path(backup_root).expanduser()
    reject_links(capture_root)
    reject_links(backup_root)
    nonoverlap(capture_root, backup_root)
    planner = {"wii": plan_wii, "gamecube": plan_gamecube}.get(meta.get("classification"))
    if planner is None:
        return {"ready": False, "blockers": ["metadata does not classify a supported Nintendo DVD platform"]}
    return planner(cfg, meta, drive, str(Path(capture_root).expanduser()), str(Path(backup_root).expanduser()), safe_component(release_name(meta, cfg)))


def wii_plan(cfg, drive, meta, args):
    return nintendo_plan(cfg, drive, meta, args)


def dispatch_nintendo(cfg, drive, meta, args, platform):
    from portable_disc_wii import run_nintendo_dvd, verify_gamecube, verify_wii
    verifier = {"wii": verify_wii, "gamecube": verify_gamecube}[platform]
    # A second fresh bounded header observation replaces the unavailable USB counter.
    # The final image and a third disc observation must still agree before filing.
    fresh = inspect(cfg, drive)
    if (fresh.get("classification") != platform or not fresh.get("fingerprint")
            or fresh.get("fingerprint") != meta.get("fingerprint")
            or fresh.get("decision") == "suppressed" or fresh.get("identity_consistency") == "changed"):
        raise ValueError(f"fresh {platform} identity is unknown, changed, or completed; no capture started")
    plan = wii_plan(cfg, drive, fresh, args) if platform == "wii" else nintendo_plan(cfg, drive, fresh, args)
    print(json.dumps({f"{platform}_capture_plan": plan}, indent=2, ensure_ascii=False))
    if not plan["ready"]:
        raise ValueError(f"{platform} capture preflight blocked: " + "; ".join(plan["blockers"]))
    fp = fresh["fingerprint"]
    try:
        record(cfg, "ripping", fingerprint=fp, drive=drive, output=plan["job_dir"], mode=f"fixed redumper {platform} DVD aggregate")
        code = run_nintendo_dvd(plan)
        if code != 0: raise RuntimeError(f"redumper exited with status {code}; source files retained")
        record(cfg, "verifying", fingerprint=fp, drive=drive, output=plan["job_dir"])
        proof = verifier(plan)
        with Path(proof["iso_path"]).open("rb") as image:
            image_identity = parse_header(image.read(128))["metadata"]
        if image_identity.get("fingerprint") != fp:
            raise ValueError("verified ISO logical identity differs from the capture source; no NAS filing")
        after = probe_drive(drive)
        if after.get("fingerprint") != fp or after.get("identity_consistency") == "changed":
            raise ValueError("post-capture disc logical identity changed; no NAS filing")
        metadata = {**fresh, "capture_completion": proof, "post_capture_fingerprint": after["fingerprint"],
                    "identity_limit": "matching logical fingerprints do not prove one unique physical disc", **program_stamp()}
        metadata_path = Path(plan["job_dir"]) / "capture-metadata.json"
        with metadata_path.open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        return ingest(cfg, argparse.Namespace(source=proof["iso_path"], backup_root=plan["backup_root"],
               backup_folder=plan["backup_folder"], metadata=str(metadata_path), confirmed_complete=True, local_root=None))
    except (Exception, KeyboardInterrupt) as exc:
        record(cfg, "failed", fingerprint=fp, drive=drive, output=plan["job_dir"], error=str(exc))
        raise


def dispatch_wii(cfg, drive, meta, args):
    return dispatch_nintendo(cfg, drive, meta, args, "wii")


def dispatch_gamecube(cfg, drive, meta, args):
    return dispatch_nintendo(cfg, drive, meta, args, "gamecube")


def _prior_dvd_evidence(cfg, fingerprint):
    evidence = []
    for row in read_events(event_path(cfg)):
        if row.get("event") == "metadata" and row.get("fingerprint") == fingerprint:
            report = row.get("report", {})
            evidence.append({key: report.get(key) for key in (
                "warning_counts", "source_integrity_warning_count", "evidence_directory",
                "report_path", "result_path", "observation_path", "status") if key in report})
    return evidence


def _disc_counter_changed(before, after):
    left, right = before.get("disc_change_count"), after.get("disc_change_count")
    return left is not None and right is not None and left != right


def _plan_leadout(plan):
    geometry = plan.get("expected_geometry")
    if not isinstance(geometry, dict):
        return None
    for key in ("leadout_lba", "sectors", "sector_count"):
        if isinstance(geometry.get(key), int):
            return geometry[key]
    return None


def _observed_leadout(metadata):
    toc = metadata.get("toc")
    if isinstance(toc, dict) and isinstance(toc.get("leadout_lba"), int):
        return toc["leadout_lba"]
    for item in metadata.get("evidence", []):
        if item.get("kind") == "toc" and isinstance(item.get("leadout_lba"), int):
            return item["leadout_lba"]
    return None


def dispatch_dvd(cfg, drive, meta, args):
    from portable_disc_dvd import plan_dvd, run_dvd, verify_dvd

    fresh = inspect(cfg, drive)
    fp = fresh.get("fingerprint")
    if (fresh.get("classification") != "dvd_video" or not fp
            or fp != meta.get("fingerprint") or fresh.get("decision") == "suppressed"
            or fresh.get("identity_consistency") == "changed"
            or _disc_counter_changed(meta, fresh)):
        raise ValueError("fresh DVD structure is unknown, changed, or completed; no preservation started")
    capture_root = args.capture_root or cfg.get("capture_root")
    if not capture_root:
        raise ValueError("configure capture_root or pass --capture-root")
    backup_root = backup_root_for(cfg, "dvd_video", args.backup_root)
    plan = plan_dvd(cfg, fresh, drive, capture_root, backup_root)
    compact = {key: plan.get(key) for key in ("job_dir", "backup_root", "backup_folder", "expected_geometry",
                                                "expected_sectors", "expected_bytes", "ready", "blockers")}
    print(json.dumps({"dvd_preservation_plan": compact}, indent=2, ensure_ascii=False))
    if not plan.get("ready"):
        raise ValueError("DVD preservation preflight blocked: " + "; ".join(plan.get("blockers", [])))
    try:
        record(cfg, "ripping", fingerprint=fp, drive=drive, output=plan["job_dir"],
               mode="fixed redumper DVD full-disc ISO preservation")
        code = run_dvd(plan)
        if code != 0:
            raise RuntimeError(f"redumper exited with status {code}; source files retained")
        record(cfg, "verifying", fingerprint=fp, drive=drive, output=plan["job_dir"])
        proof = verify_dvd(plan)
        if proof.get("fingerprint") != fp:
            raise ValueError("verified ISO structure fingerprint differs from the source; no NAS filing")
        if (proof.get("classification") != "dvd_video" or not proof.get("completion_proof")
                or not proof.get("read_state") or not proof.get("image_geometry")
                or not proof.get("iso_structure")):
            raise ValueError("DVD verification proof lacks read state, image geometry, or ISO structure")
        if proof.get("first_pass_scsi_errors") != 0:
            raise ValueError("DVD first-pass SCSI error count is not zero; no NAS filing")
        after = probe_drive(drive)
        if (after.get("classification") != "dvd_video" or after.get("fingerprint") != fp
                or after.get("identity_consistency") == "changed" or _disc_counter_changed(fresh, after)
                or _disc_counter_changed(meta, after)):
            raise ValueError("post-capture DVD structure changed or became unknown; no NAS filing")
        expected_leadout, observed_leadout = _plan_leadout(plan), _observed_leadout(after)
        if expected_leadout is not None and observed_leadout is not None and expected_leadout != observed_leadout:
            raise ValueError("post-capture DVD TOC leadout differs from planned image geometry; no NAS filing")
        source_quality = "redumper read state, image geometry, and ISO structure verified; source integrity warnings are diagnostics, not an independent physical EDC claim"
        warning_history = _prior_dvd_evidence(cfg, fp)
        metadata = {
            "classification": "dvd_video", "fingerprint": fp,
            "metadata_status": "pending", "title": None, "year": None,
            "volume_label": fresh.get("volume_label"), "capture_completion": proof,
            "capture_job_dir": str(Path(plan["job_dir"]).absolute()),
            "iso_relative_path": Path(proof["iso_path"]).resolve().relative_to(Path(plan["job_dir"]).resolve()).as_posix(),
            "iso_sha256": proof.get("iso_sha256"),
            "post_capture_fingerprint": after.get("fingerprint"),
            "source_quality": source_quality,
            "playability": "unknown", "css": "unknown",
            "metadata_query_evidence": warning_history,
            **program_stamp(),
        }
        metadata_path = Path(plan["job_dir"]) / "capture-metadata.json"
        with metadata_path.open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        return ingest(cfg, argparse.Namespace(source=plan["job_dir"], backup_root=backup_root,
               backup_folder=plan["backup_folder"], metadata=str(metadata_path), confirmed_complete=True, local_root=None))
    except (Exception, KeyboardInterrupt) as exc:
        record(cfg, "preservation_incomplete", fingerprint=fp, drive=drive,
               output=plan.get("job_dir"), error=str(exc))
        record(cfg, "failed", fingerprint=fp, drive=drive, output=plan.get("job_dir"), error=str(exc))
        raise


def placement_lock(cfg, archive):
    return drive_lock(cfg, "playable:" + str(Path(archive).absolute()))


def _notice_key(report):
    return tuple(report.get(key) for key in ("fingerprint", "archive", "host", "destination", "sha256"))


def notify_completion(cfg, report, safe_exchange):
    digest = report.get("sha256")
    if (report.get("verification") != "verified" or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != report.get("source_sha256")
            or not report.get("archive") or not report.get("source") or not report.get("destination")
            or not report.get("host")):
        raise ValueError("completion notice requires verified source and destination SHA-256 values and exact paths")
    key = _notice_key(report)
    lock_name = "notification:" + hashlib.sha256(json.dumps(key).encode()).hexdigest()
    with drive_lock(cfg, lock_name):
        already = any(row.get("event") == "completion_notice" and tuple(row.get(k) for k in
                      ("fingerprint", "archive", "host", "destination", "sha256")) == key
                      for row in read_events(event_path(cfg)))
        if already:
            return
        message = (f"Backup and EmuDeck copy verified: {report.get('title') or 'Unknown title'} "
                   f"({report['platform']})\nArchive: {report['archive']}\nPlayable: "
                   f"{report['host']}:{report['destination']}\nSHA-256: {report['sha256']}\n"
                   f"Resolved playable path: {report.get('resolved_destination', report['destination'])}\n"
                   f"NAS SHA-256: {report['source_sha256']}\n"
                   f"Verification: {report['verification']}\nSafe to exchange disc: "
                   f"{'yes; optical drive lock released' if safe_exchange is True else safe_exchange}")
        print(message)
        delivery = {"delivery": "unsupported", "cause": "no supported desktop notification capability"}
        try:
            if os.name == "nt":
                delivery = windows_notification(message)
            elif sys.platform.startswith("linux"):
                delivery = linux_notification(message)
        except Exception as exc:
            delivery = {"delivery": "failed", "cause": str(exc)}
        record(cfg, "completion_notice", **{k: report.get(k) for k in
               ("fingerprint", "archive", "source", "title", "platform", "host", "destination",
                "resolved_destination", "source_sha256", "sha256", "verification")},
               safe_to_exchange=True if safe_exchange is True else None,
               exchange_assessment="verified after optical drive lock release" if safe_exchange is True else safe_exchange)
        record(cfg, "notification_delivery", delivery=delivery["delivery"], cause=delivery.get("cause"),
               fingerprint=report.get("fingerprint"), destination=report.get("destination"))
        print(f"Desktop notification: {delivery['delivery']}" +
              (f"; {delivery['cause']}" if delivery.get("cause") else "; visible delivery requires operator confirmation"))


def linux_notification(message):
    executable = shutil.which("notify-send")
    if not executable:
        return {"delivery": "unsupported", "cause": "notify-send is not installed"}
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return {"delivery": "unsupported", "cause": "no interactive desktop session is available"}
    result = subprocess.run([executable, "Portable disc workflow", message], shell=False,
                            capture_output=True, text=True, timeout=10, check=False)
    return {"delivery": "submitted" if result.returncode == 0 else "failed",
            "cause": None if result.returncode == 0 else f"notify-send exited {result.returncode}: {result.stderr.strip()}"}


def windows_notification(message):
    if not sys.platform.startswith("win") or not os.environ.get("SESSIONNAME"):
        return {"delivery": "unsupported", "cause": "no interactive Windows desktop session is available"}
    script = r'''$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
if (-not [Environment]::UserInteractive) {
  [Console]::Out.WriteLine('{"delivery":"unsupported","cause":"no interactive Windows desktop session is available"}')
  exit 0
}
$icon = New-Object System.Windows.Forms.NotifyIcon
try {
  $icon.Icon = [System.Drawing.SystemIcons]::Information
  $icon.Visible = $true
  $icon.BalloonTipTitle = 'Portable disc workflow'
  $icon.BalloonTipText = $request.message
  $icon.ShowBalloonTip(5000)
  $until = [DateTime]::UtcNow.AddSeconds(5)
  while ([DateTime]::UtcNow -lt $until) {
    [System.Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 50
  }
  [Console]::Out.WriteLine('{"delivery":"submitted"}')
} finally { $icon.Visible = $false; $icon.Dispose() }
'''
    result = subprocess.run(["powershell.exe", "-NoProfile", "-STA", "-Command", script],
                            input=json.dumps({"message": message}), capture_output=True,
                            text=True, shell=False, timeout=10, check=False)
    if result.returncode:
        return {"delivery": "failed", "cause": f"NotifyIcon helper exited {result.returncode}: {result.stderr.strip()}"}
    try:
        reply = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"delivery": "failed", "cause": "NotifyIcon helper returned no delivery status"}
    return {"delivery": reply.get("delivery", "failed"), "cause": reply.get("cause")}


def place_and_notify(cfg, archive, safe_exchange):
    from portable_disc_playable import place_backup
    with placement_lock(cfg, archive):
        report = place_backup(cfg, archive)
        digest = report.get("sha256")
        if (report.get("verification") != "verified" or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest != report.get("source_sha256")):
            raise ValueError("playable destination hash does not match the verified NAS source")
        completed = any(row.get("event") == "local_complete" and _notice_key(row) == _notice_key(report)
                        and row.get("verification") == "verified" for row in read_events(event_path(cfg)))
        if not completed:
            record(cfg, "local_complete", **report)
    notify_completion(cfg, report, safe_exchange)
    return report


def resume_archive(cfg, archive):
    if _archive_metadata(archive).get("classification") == "dvd_video":
        return finish_archive(cfg, archive, "not assessed; archive verification only")
    return place_and_notify(cfg, archive, "not assessed; archive placement only")


def _archive_metadata(archive):
    marker = Path(archive) / "backup_complete.json"
    manifest = json.loads(marker.read_text(encoding="utf-8"))
    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("archive completion marker has no metadata object")
    return metadata


def verified_dvd_archive(archive):
    """Read and hash an existing DVD archive without events, notices, or writes."""
    root = Path(archive).expanduser().absolute()
    marker = root / "backup_complete.json"
    reject_links(marker)
    manifest = json.loads(marker.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        raise ValueError("DVD archive requires a version-1 completion marker")
    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("classification") != "dvd_video":
        raise ValueError("archive is not a completed DVD-video preservation job")
    fingerprint = metadata.get("fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"dvd-video-structure:[0-9a-f]{64}", fingerprint):
        raise ValueError("DVD archive has no valid structural fingerprint")
    proof = metadata.get("capture_completion")
    if not isinstance(proof, dict) or any(proof.get(key) is not True for key in ("complete", "verified", "matching")):
        raise ValueError("DVD archive lacks completed preservation proof")
    _, files = safe_tree(root / "data")
    records = file_records(files)
    if records != manifest.get("records"):
        raise ValueError("DVD archive reread does not match backup_complete.json")
    relative = metadata.get("iso_relative_path")
    selected = next(((rel, path) for rel, path in files if rel == relative), None)
    iso_record = next((row for row in records if row["path"] == relative), None)
    if selected is None or not iso_record or "ISO-9660 (CD001)" not in iso_record["signatures"]:
        raise ValueError("DVD archive metadata does not select a verified ISO image")
    return {"archive": str(root), "iso_path": str(selected[1]), "iso_sha256": iso_record["sha256"],
            "iso_bytes": iso_record["bytes"], "fingerprint": fingerprint, "metadata": metadata,
            "marker_sha256": hash_file(marker),
            "records_digest": hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def archive_inspection_root(cfg, archive):
    """Require local evidence, separate from the read-only archive input."""
    if os.name != "nt" or not cfg.get("profiles", {}).get("windows", {}).get("enabled", False):
        raise ValueError("dvd-archive-info requires the enabled Windows profile")
    configured = cfg.get("inspection_root")
    if not configured:
        raise ValueError("dvd-archive-info requires a configured local inspection_root")
    root = Path(configured).expanduser()
    if not root.is_absolute() or str(root).startswith(("\\\\", "//")) or not root.drive:
        raise ValueError("archive inspection evidence must use an absolute local Windows path")
    import ctypes
    if ctypes.windll.kernel32.GetDriveTypeW(root.drive + "\\") not in {2, 3}:
        raise ValueError("archive inspection evidence must use a local removable or fixed drive")
    nonoverlap(root, archive)
    if not root.is_dir():
        raise ValueError("archive inspection_root must already exist")
    return root


def run_dvd_archive_info(cfg, archive, report_json=False):
    """Inspect only a hash-verified archived ISO; never resume, capture, or notify."""
    from portable_disc_video import inspect_archive
    root = archive_inspection_root(cfg, archive)
    source = verified_dvd_archive(archive)
    evidence_dir = root / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex)
    report = inspect_archive(cfg, source, evidence_dir)
    consistency_error = None
    try:
        after = verified_dvd_archive(archive)
        if after != source:
            raise ValueError("DVD archive changed during ISO information query")
    except (OSError, ValueError, TypeError) as exc:
        consistency_error = str(exc)
    result = {**report, "report_path": str(evidence_dir / "report.json"), "result_path": str(evidence_dir / "result.json"),
              "evidence_directory": str(evidence_dir), "source_consistency_error": consistency_error,
              "source_consistency_scope": "matching before/after archive hashes; not an immutable snapshot against concurrent writers",
              "capture_started": False, "extraction_started": False, "playability": "not_assessed"}
    if consistency_error:
        result["status"] = "incomplete"
        result["blockers"] = [*result.get("blockers", []), consistency_error]
    with (evidence_dir / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    summary = {key: result.get(key) for key in ("status", "report_path", "result_path", "evidence_directory", "exit_code",
               "blockers", "unknowns", "source_consistency_error", "capture_started", "extraction_started", "playability")}
    summary.update({"archive": source["archive"], "iso_path": source["iso_path"], "iso_sha256": source["iso_sha256"],
                    "title_count": result.get("robot", {}).get("title_count"),
                    "source_warning_count": len(result.get("robot", {}).get("source_integrity_warnings", []))})
    if result.get("status") != "archive_inspected":
        summary["native_message_samples"] = [{"code": item.get("code"), "message": str(item.get("message", ""))[:240]}
                                             for item in result.get("robot", {}).get("messages", [])[-3:]]
    print(json.dumps(result if report_json else summary, separators=(",", ":"), ensure_ascii=False))
    return 0 if result.get("status") == "archive_inspected" and not consistency_error else 2


def verified_archive_inspection(path, source):
    """Tie an existing successful ISO inspection to the current verified archive."""
    from portable_disc_video import parse_robot
    receipt = Path(path).expanduser().absolute()
    reject_links(receipt)
    result = json.loads(receipt.read_text(encoding="utf-8"))
    if not isinstance(result, dict) or result.get("status") != "archive_inspected" or result.get("exit_code") != 0:
        raise ValueError("extraction requires a successful archive information result")
    if "source_consistency_error" not in result or result["source_consistency_error"] is not None:
        raise ValueError("archive information lacks a successful final consistency receipt")
    identity = result.get("source_info")
    keys = ("archive", "iso_path", "iso_sha256", "iso_bytes", "records_digest", "fingerprint", "marker_sha256")
    if not isinstance(identity, dict) or any(identity.get(key) != source.get(key) for key in keys):
        raise ValueError("archive information does not match the verified source archive")
    raw = receipt.parent / "stdout.log"
    reject_links(raw)
    raw_bytes = raw.read_bytes()
    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    if raw_hash != result.get("stdout_sha256"):
        raise ValueError("archive information raw log hash does not match the saved receipt")
    if parse_robot(raw_bytes.decode("utf-8", errors="replace")) != result.get("robot"):
        raise ValueError("saved title/stream inventory differs from the raw information log")
    result["inspection_input"] = {"path": str(receipt), "sha256": hash_file(receipt),
                                  "raw_path": str(raw), "raw_sha256": raw_hash}
    return result


def run_dvd_archive_extract(cfg, archive, inspection_path, report_json=False):
    """Derive local title candidates only; never publish a library or send notices."""
    from portable_disc_extract import plan_extract, extract_archive
    root = archive_inspection_root({**cfg, "inspection_root": cfg.get("capture_root")}, archive)
    source = verified_dvd_archive(archive)
    inspection = verified_archive_inspection(inspection_path, source)
    job = root / ("dvd-derivatives-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex)
    nonoverlap(job, inspection_path)
    plan = plan_extract(cfg, source, inspection, job)
    if not plan.get("ready"):
        print(json.dumps({"status": "preflight_failed", "blockers": plan.get("blockers", []),
                          "extraction_started": False, "archive": source["archive"]}, separators=(",", ":")))
        return 2
    report = extract_archive(plan)
    consistency_error = None
    try:
        if verified_dvd_archive(archive) != source:
            raise ValueError("archive changed during local extraction")
        original = inspection["inspection_input"]
        if hash_file(original["path"]) != original["sha256"] or hash_file(original["raw_path"]) != original["raw_sha256"]:
            raise ValueError("source inspection evidence changed during local extraction")
    except (OSError, ValueError, TypeError) as exc:
        consistency_error = str(exc)
    result = {**report, "source_consistency_error": consistency_error,
              "source_consistency_scope": "matching before/after archive hashes; not an immutable snapshot against concurrent writers",
              "library_filed": False, "playback_acceptance": "not_assessed", "result_path": str(job / "result.json")}
    if consistency_error:
        result["status"] = "incomplete"
        result["blockers"] = [*result.get("blockers", []), consistency_error]
    with (job / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    summary = {key: result.get(key) for key in ("status", "blockers", "result_path", "source_consistency_error",
               "library_filed", "playback_acceptance", "title_count", "verified_title_count", "stream_selection_contract")}
    print(json.dumps(result if report_json else summary, separators=(",", ":"), ensure_ascii=False))
    return 0 if result.get("status") == "derivatives_inspected" and not consistency_error else 2


def local_recheck_plan(cfg, job):
    """Validate local prior evidence only; never reopen its recorded NAS source."""
    from portable_disc_extract import _tool, _title_map
    from portable_disc_video import parse_robot
    root = Path(job).expanduser()
    if not root.is_absolute() or str(root).startswith(("\\\\", "//")) or not root.drive:
        raise ValueError("recheck source must be an absolute local Windows job path")
    import ctypes
    if ctypes.windll.kernel32.GetDriveTypeW(root.drive + "\\") not in {2, 3}:
        raise ValueError("recheck source must use a local fixed or removable drive")
    receipt = root / "result.json"
    reject_links(receipt)
    prior = json.loads(receipt.read_text(encoding="utf-8"))
    if (not isinstance(prior, dict) or prior.get("exit_code") != 0
            or "source_consistency_error" not in prior or prior["source_consistency_error"] is not None):
        raise ValueError("prior job lacks successful native extraction and recorded source consistency")
    if not isinstance(prior.get("source"), dict) or not isinstance(prior.get("inspection_input"), dict):
        raise ValueError("prior job lacks its source and inspection evidence")
    original = prior.get("inspection_input", {})
    inspection_path = Path(original.get("path", ""))
    if not inspection_path.is_absolute() or str(inspection_path).startswith(("\\\\", "//")):
        raise ValueError("prior inspection receipt must be local")
    if ctypes.windll.kernel32.GetDriveTypeW(inspection_path.drive + "\\") not in {2, 3}:
        raise ValueError("prior inspection receipt cannot use a network or optical drive")
    inspection = verified_archive_inspection(inspection_path, prior["source"])
    if inspection["inspection_input"]["sha256"] != original.get("sha256"):
        raise ValueError("prior inspection receipt changed since extraction")
    if inspection["inspection_input"]["raw_sha256"] != original.get("raw_sha256"):
        raise ValueError("prior inspection raw log changed since extraction")
    title_map = _title_map(inspection)
    native_log = root / "makemkv-stdout.log"
    reject_links(native_log)
    native_hash = hash_file(native_log)
    if native_hash != prior.get("logs", {}).get("makemkv-stdout.log", {}).get("sha256"):
        raise ValueError("prior MakeMKV completion log changed")
    messages = parse_robot(native_log.read_text(encoding="utf-8", errors="replace"))["messages"]
    saved_count = any(message["code"] == 5005 and message["params"] == [str(len(title_map))] for message in messages)
    if not saved_count:
        raise ValueError("prior MakeMKV log does not confirm the expected saved-title count")
    rows = prior.get("titles")
    if (not isinstance(rows, list) or len(rows) != len(title_map) or prior.get("title_count") != len(title_map)
            or any(not isinstance(row, dict) for row in rows)):
        raise ValueError("prior job does not record every title")
    seen = set()
    for row in rows:
        title_id = row.get("title_id")
        if title_id not in title_map or title_id in seen:
            raise ValueError("prior title identity is missing or duplicated")
        seen.add(title_id)
        target = root / "titles" / f"title-{title_id:03}.mkv"
        if Path(row.get("path", "")) != target:
            raise ValueError("prior title path is outside its neutral local job location")
        reject_links(target)
        if not target.is_file() or target.stat().st_size != row.get("bytes") or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))):
            raise ValueError("prior local title is absent or its recorded size/hash is invalid")
    paths, hashes = {}, {}
    for name in ("ffprobe", "ffmpeg"):
        paths[name], hashes[name] = _tool(cfg.get("tools", {}).get(name), name)
    return {"ready": True, "old_job": str(root), "old_result_sha256": hash_file(receipt),
            "old_native_log_sha256": native_hash, "source": prior["source"], "inspection": inspection,
            "titles": rows, "title_count": len(title_map), "title_map": title_map,
            "tools": {name: str(path) for name, path in paths.items()}, "tool_sha256": hashes}


def run_dvd_derivatives_recheck(cfg, job, report_json=False):
    """Save a new local verification receipt without extraction or NAS access."""
    from portable_disc_extract import verify_existing
    base = archive_inspection_root(cfg, job)
    plan = local_recheck_plan(cfg, job)
    directory = base / ("dvd-recheck-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex)
    report = verify_existing(plan, directory)
    consistency_error = None
    try:
        if local_recheck_plan(cfg, job) != plan:
            raise ValueError("local source evidence changed during recheck")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        consistency_error = str(exc)
    result = {**report, "source_consistency_error": consistency_error, "library_filed": False,
              "playback_acceptance": "not_assessed", "result_path": str(directory / "result.json"),
              "archive_verification_scope": "prior extraction receipt only; NAS archive was not reopened in this recheck"}
    if consistency_error:
        result["status"] = "derivatives_incomplete"
        result["blockers"] = [*result.get("blockers", []), consistency_error]
    with (directory / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    summary = {key: result.get(key) for key in ("status", "blockers", "result_path", "title_count", "verified_title_count",
               "source_consistency_error", "archive_verification_scope", "library_filed", "playback_acceptance")}
    print(json.dumps(result if report_json else summary, separators=(",", ":"), ensure_ascii=False))
    return 0 if result.get("status") == "derivatives_inspected" and not consistency_error else 2


def run_dvd_library_plan(cfg, job, verification_path, preview=False, report_json=False):
    """Create a local title-mapping worksheet; optional JPEG previews stay local."""
    from portable_disc_extract import dvd_library_plan
    base = archive_inspection_root(cfg, job)
    plan = local_recheck_plan(cfg, job)
    verification = Path(verification_path).expanduser().absolute()
    reject_links(verification)
    if not verification.is_file() or verification.suffix.casefold() != ".json":
        raise ValueError("verification must be an existing local JSON receipt")
    resolved_base = base.resolve(strict=True)
    resolved_verification = verification.resolve(strict=True)
    try:
        resolved_verification.relative_to(resolved_base)
    except ValueError as exc:
        raise ValueError("verification receipt must be inside the configured local inspection root") from exc
    verification_hash = hash_file(verification)
    saved = json.loads(verification.read_text(encoding="utf-8"))
    destination = base / ("dvd-library-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex)
    nonoverlap(destination, job)
    nonoverlap(destination, verification)
    result = dvd_library_plan(plan, saved, verification, verification_hash, destination, preview=preview)
    consistency_error = None
    try:
        if local_recheck_plan(cfg, job) != plan:
            raise ValueError("existing local job evidence changed during library planning")
        if hash_file(verification) != verification_hash:
            raise ValueError("local verification receipt changed during library planning")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        consistency_error = str(exc)
    if consistency_error:
        result["status"] = "incomplete"
        result.setdefault("blockers", []).append(consistency_error)
    result["result_path"] = str(destination / "result.json")
    result["source_consistency_error"] = consistency_error
    with (destination / "result.json").open("w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    summary = {key: result.get(key) for key in ("status", "title_count", "pending_mapping_count",
        "blockers", "result_path", "preview")}
    print(json.dumps(result if report_json else summary, separators=(",", ":"), ensure_ascii=False))
    return 0 if result.get("status") == "pending_mapping" and not consistency_error else 2


def finish_archive(cfg, archive, safe_exchange):
    """Verify DVD archive bytes and issue one durable metadata-pending notice."""
    metadata = _archive_metadata(archive)
    if metadata.get("classification") != "dvd_video":
        return place_and_notify(cfg, archive, safe_exchange)
    archive_path = Path(archive).absolute()
    manifest = json.loads((archive_path / "backup_complete.json").read_text(encoding="utf-8"))
    _, files = safe_tree(archive_path / "data")
    records = file_records(files)
    if records != manifest.get("records"):
        raise ValueError("DVD archive reread does not match backup_complete.json")
    records_digest = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    fingerprint = metadata.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        raise ValueError("DVD archive metadata has no structural fingerprint")
    key = hashlib.sha256(json.dumps([fingerprint, str(archive_path), records_digest], separators=(",", ":")).encode()).hexdigest()
    iso_relative = metadata.get("iso_relative_path")
    iso_record = next((item for item in records if item.get("path") == iso_relative), None)
    iso_path = str(archive_path / "data" / iso_relative) if iso_record else None
    iso_hash = iso_record.get("sha256") if iso_record else metadata.get("iso_sha256")
    label = metadata.get("volume_label")
    with drive_lock(cfg, "dvd-notice:" + key):
        rows = read_events(event_path(cfg))
        already = any(row.get("event") == "preservation_notice" and row.get("notice_key") == key for row in rows)
        if not any(row.get("event") == "metadata_pending" and row.get("notice_key") == key for row in rows):
            record(cfg, "metadata_pending", notice_key=key, fingerprint=fingerprint,
                   archive=str(archive_path), records_digest=records_digest)
        if already:
            return {"verification": "verified", "classification": "dvd_video", "fingerprint": fingerprint,
                    "archive": str(archive_path), "records_digest": records_digest, "notice": "already_sent"}
        message = ("Archive verified; metadata and playable library placement pending\n"
                   f"DVD-Video; DVD label {label if label else 'unknown'}\n"
                   f"Archive: {archive_path}\nRecords SHA-256: {records_digest}\n"
                   f"ISO: {iso_path or 'not available'}\nISO SHA-256: {iso_hash or 'not available'}\n"
                   f"Safe to exchange disc: {'yes; optical drive lock released' if safe_exchange is True else safe_exchange}")
        record(cfg, "preservation_notice", notice_key=key, fingerprint=fingerprint,
               archive=str(archive_path), records_digest=records_digest,
               iso_path=iso_path, iso_sha256=iso_hash, volume_label=label,
               safe_to_exchange=True if safe_exchange is True else None)
        delivery = {"delivery": "unsupported", "cause": "no supported desktop notification capability"}
        try:
            if os.name == "nt":
                delivery = windows_notification(message)
            elif sys.platform.startswith("linux"):
                delivery = linux_notification(message)
        except Exception as exc:
            delivery = {"delivery": "failed", "cause": str(exc)}
        record(cfg, "notification_delivery", delivery=delivery["delivery"], cause=delivery.get("cause"),
               fingerprint=fingerprint, archive=str(archive_path), records_digest=records_digest)
        print(message)
        print(f"Desktop notification: {delivery['delivery']}" +
              (f"; {delivery['cause']}" if delivery.get("cause") else "; visible delivery requires operator confirmation"))
        return {"verification": "verified", "classification": "dvd_video", "fingerprint": fingerprint,
                "archive": str(archive_path), "records_digest": records_digest,
                "notice": "sent", "delivery": delivery["delivery"]}


def latest_archive(cfg, fingerprint):
    rows = read_events(event_path(cfg))
    for row in reversed(rows):
        if row.get("event") == "backup_complete" and row.get("fingerprint") == fingerprint and row.get("destination"):
            return row["destination"]
    return None


def resume_pending_once(cfg):
    completed = {_notice_key(row) for row in read_events(event_path(cfg)) if row.get("event") == "local_complete" and row.get("verification") == "verified"}
    seen = set()
    for row in read_events(event_path(cfg)):
        if row.get("event") != "backup_complete" or not row.get("destination"):
            continue
        archive = row["destination"]
        nas_verified = False
        try:
            if _archive_metadata(archive).get("classification") == "dvd_video":
                finish_archive(cfg, archive, "not assessed; archive verification only")
                continue
            from portable_disc_playable import archive_info, placement_target, playable_filename
            info = archive_info(archive)
            nas_verified = True
            target = placement_target(cfg, info["metadata"])
            candidate = {"fingerprint": info["fingerprint"], "archive": info["archive"], "host": target["host"],
                         "destination": target["directory"] + "/" + playable_filename(info), "sha256": info["sha256"]}
            key = _notice_key(candidate)
            if key in seen or key in completed:
                continue
            seen.add(key)
            place_and_notify(cfg, archive, "not assessed; archive placement only")
        except Exception as exc:
            try:
                dvd_archive = _archive_metadata(archive).get("classification") == "dvd_video"
            except Exception:
                dvd_archive = False
            if dvd_archive:
                record(cfg, "failed", fingerprint=row.get("fingerprint"), archive=archive,
                       stage="archive_verification", error=str(exc))
                print(f"DVD archive verification/metadata notice pending or failed: {exc}", file=sys.stderr)
            else:
                record(cfg, "playable_pending", fingerprint=row.get("fingerprint"), archive=archive, cause=str(exc))
                prefix = "NAS backup verified; EmuDeck copy pending/failed" if nas_verified else "NAS archive verification failed; EmuDeck copy not attempted"
                print(f"{prefix}: {exc}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--version", action="version", version=version_text())
    p.add_argument("--config", default="config/portable-disc-workflow.example.json")
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("probe"); q.add_argument("--drive", required=True)
    q = sub.add_parser("dvd-info"); q.add_argument("--drive", required=True); q.add_argument("--report-json", action="store_true", help="print the complete saved MakeMKV report")
    q = sub.add_parser("dvd-archive-info"); q.add_argument("--archive", required=True); q.add_argument("--report-json", action="store_true", help="print the complete saved ISO information report")
    q = sub.add_parser("dvd-archive-extract"); q.add_argument("--archive", required=True); q.add_argument("--inspection", required=True, help="existing successful archive-info result.json"); q.add_argument("--report-json", action="store_true")
    q = sub.add_parser("dvd-derivatives-recheck"); q.add_argument("--job", required=True, help="existing local derivative job, never a disc or NAS input"); q.add_argument("--report-json", action="store_true")
    q = sub.add_parser("dvd-library-plan"); q.add_argument("--job", required=True, help="existing local derivative job"); q.add_argument("--verification", required=True, help="latest local derivative recheck result.json"); q.add_argument("--preview", action="store_true", help="save three bounded JPEG inspection frames per verified title"); q.add_argument("--report-json", action="store_true")
    q = sub.add_parser("vlc-info"); q.add_argument("--report-json", action="store_true", help="print the complete saved VLC report")
    q = sub.add_parser("once"); q.add_argument("--drive", required=True); q.add_argument("--execute", action="store_true", help="run the matching configured capture adapter"); q.add_argument("--metadata", help="manual per-run metadata for Linux redumper only"); q.add_argument("--report-json", action="store_true", help="print the complete saved MakeMKV report for DVD metadata")
    q.add_argument("--capture-root"); q.add_argument("--backup-root")
    q = sub.add_parser("watch"); q.add_argument("--drive", action="append"); q.add_argument("--interval", type=float, default=3.0); q.add_argument("--execute", action="store_true", help="run matching adapters only for identified, unsuppressed media"); q.add_argument("--report-json", action="store_true", help="print the complete saved MakeMKV report for DVD metadata")
    q.add_argument("--capture-root"); q.add_argument("--backup-root")
    q = sub.add_parser("ingest"); q.add_argument("--source", required=True); q.add_argument("--backup-root"); q.add_argument("--backup-folder"); q.add_argument("--metadata", required=True); q.add_argument("--confirmed-complete", action="store_true"); q.add_argument("--local-root")
    q = sub.add_parser("retry"); q.add_argument("fingerprint", help="explicitly clears suppression by appending retry event")
    q = sub.add_parser("resume"); q.add_argument("--backup", required=True, help="existing NAS archive folder")
    q = p.parse_args()
    try:
        cfg = load_config(q.config)
        if q.command == "dvd-derivatives-recheck":
            return run_dvd_derivatives_recheck(cfg, q.job, report_json=q.report_json)
        if q.command == "dvd-library-plan":
            return run_dvd_library_plan(cfg, q.job, q.verification, preview=q.preview, report_json=q.report_json)
        if q.command == "dvd-archive-extract":
            return run_dvd_archive_extract(cfg, q.archive, q.inspection, report_json=q.report_json)
        if q.command == "dvd-archive-info":
            return run_dvd_archive_info(cfg, q.archive, report_json=q.report_json)
        if q.command == "vlc-info":
            return run_vlc_info(cfg, report_json=q.report_json)
        if q.command in {"probe", "once", "watch", "dvd-info"} and sys.platform.startswith("linux") and not cfg.get("profiles", {}).get("linux", {}).get("enabled", False):
            raise ValueError("Linux profile is disabled in config")
        if q.command == "dvd-info" and os.name != "nt":
            raise ValueError("dvd-info currently supports Windows drive letters only")
        if q.command == "dvd-info" and os.name == "nt" and not cfg.get("profiles", {}).get("windows", {}).get("enabled", False):
            raise ValueError("Windows profile is disabled in config")
        if q.command == "ingest":
            archive = ingest(cfg, q)
            if archive:
                metadata = json.loads((Path(archive) / "backup_complete.json").read_text(encoding="utf-8"))["metadata"]
                if metadata.get("classification") == "dvd_video":
                    print(json.dumps(finish_archive(cfg, archive, "not assessed; archive verification only"), indent=2, ensure_ascii=False))
                elif metadata.get("classification") in {"gamecube", "wii"}:
                    try:
                        print(json.dumps(place_and_notify(cfg, archive, "not assessed; archive placement only"), indent=2, ensure_ascii=False))
                    except Exception as exc:
                        record(cfg, "playable_pending", fingerprint=metadata.get("fingerprint"), archive=archive, cause=str(exc))
                        print(f"NAS backup verified; EmuDeck copy pending/failed: {exc}", file=sys.stderr)
                        return 2
        elif q.command == "resume":
            try:
                print(json.dumps(resume_archive(cfg, q.backup), indent=2, ensure_ascii=False))
            except Exception as exc:
                try:
                    metadata = _archive_metadata(q.backup)
                    if metadata.get("classification") == "dvd_video":
                        record(cfg, "failed", fingerprint=metadata.get("fingerprint"), archive=q.backup,
                               stage="archive_verification", error=str(exc))
                        print(f"DVD archive verification/metadata notice pending or failed: {exc}", file=sys.stderr)
                        return 2
                    from portable_disc_playable import archive_info
                    info = archive_info(q.backup)
                    record(cfg, "playable_pending", fingerprint=info["fingerprint"], archive=info["archive"], cause=str(exc))
                    print(f"NAS backup verified; EmuDeck copy pending/failed: {exc}", file=sys.stderr)
                except Exception:
                    raise exc
                return 2
        elif q.command == "retry":
            if q.fingerprint in cfg.get("suppressed_fingerprints", []):
                raise ValueError("configured completed fingerprints cannot be retried")
            if any(r.get("fingerprint") == q.fingerprint and r.get("event") in {"backup_complete", "local_complete"} for r in read_events(event_path(cfg))):
                raise ValueError("completed fingerprints cannot be retried")
            record(cfg, "manual", fingerprint=q.fingerprint, action="explicit-retry")
            print("Retry recorded for an incomplete attempt. Inspect and start manually.")
        elif q.command == "once" and q.metadata and sys.platform.startswith("linux"):
            devname = Path(q.drive).name
            sg_sys = (Path("/sys/class/scsi_generic") / devname / "device").resolve(strict=True)
            sr_drive = next(("/dev/" + x.name for x in Path("/sys/class/block").glob("sr*") if (x / "device").resolve() == sg_sys), None)
            if sr_drive is None: raise ValueError("cannot map the sg device to an optical block device")
            with drive_lock(cfg, sr_drive):
                manual_meta = json.loads(Path(q.metadata).read_text(encoding="utf-8"))
                fp = manual_meta.get("fingerprint")
                if not isinstance(fp, str) or not fp.strip():
                    raise ValueError("manual capture needs an explicit logical-disc fingerprint in metadata")
                if is_suppressed(cfg, fp): print("Suppressed; no tool started.")
                elif not q.execute: print("Manual classification loaded; no tool started. Pass --execute to launch redumper.")
                else:
                    command, manual_meta, outdir = redumper_command(cfg, q.drive, q.metadata)
                    record(cfg, "ripping", fingerprint=fp, drive=q.drive, output=str(outdir), mode="redumper explicit manual dispatch")
                    try:
                        result = subprocess.run(command, shell=False, check=False)
                    except OSError as exc:
                        record(cfg, "failed", fingerprint=fp, drive=q.drive, error=str(exc)); raise
                    if result.returncode:
                        record(cfg, "failed", fingerprint=fp, drive=q.drive, exit_code=result.returncode)
                        raise RuntimeError(f"redumper exited with status {result.returncode}; retry requires explicit command")
                    print("redumper exited. Confirm output manually, then run ingest; exit status does not prove completion.")
        elif q.command == "probe":
            with drive_lock(cfg, q.drive):
                print(json.dumps(inspect(cfg, q.drive), indent=2, ensure_ascii=False))
        elif q.command == "dvd-info":
            with drive_lock(cfg, q.drive):
                m = inspect(cfg, q.drive)
                run_dvd_info(cfg, q.drive, m, report_json=q.report_json)
        elif q.command == "once":
            archive_to_place = None
            archive_classification = None
            with drive_lock(cfg, q.drive):
                m = inspect(cfg, q.drive)
                if q.command == "probe":
                    print(json.dumps(m, indent=2, ensure_ascii=False))
                elif m.get("decision") == "suppressed":
                    show_probe(cfg, q.drive, log=True, metadata=m)
                    archive_to_place = latest_archive(cfg, m.get("fingerprint")) if q.execute else None
                    archive_classification = m.get("classification")
                    if not archive_to_place: print("Suppressed; no tool started.")
                elif m.get("classification") == "dvd_video" and q.execute:
                    archive_to_place = dispatch_dvd(cfg, q.drive, m, q)
                    archive_classification = "dvd_video"
                elif m.get("classification") == "dvd_video":
                    print(json.dumps(_dvd_probe_summary(m), separators=(",", ":"), ensure_ascii=False))
                else:
                    show_probe(cfg, q.drive, log=True, metadata=m)
                    if m.get("classification") == "ps3":
                        if q.execute: dispatch_ps3(cfg, q.drive, m)
                        else: print("PS3 GUI configured; no tool started. Pass --execute to launch it.")
                    elif m.get("classification") == "wii":
                        if q.execute: archive_to_place = dispatch_wii(cfg, q.drive, m, q)
                        else: print(json.dumps({"wii_capture_plan": wii_plan(cfg, q.drive, m, q)}, indent=2))
                    elif m.get("classification") == "gamecube":
                        if q.execute: archive_to_place = dispatch_gamecube(cfg, q.drive, m, q)
                        else: print(json.dumps({"gamecube_capture_plan": nintendo_plan(cfg, q.drive, m, q)}, indent=2))
                    elif q.execute: raise ValueError("no matching automatic capture handler is available; execution refused")
                    else: print("No matching automatic capture handler is available for this evidence; no tool started.")
            if isinstance(archive_to_place, (str, os.PathLike)) and archive_to_place:
                try:
                    if archive_classification == "dvd_video":
                        finish_archive(cfg, archive_to_place, True)
                    else:
                        place_and_notify(cfg, archive_to_place, True)
                except Exception as exc:
                    if archive_classification == "dvd_video":
                        record(cfg, "failed", fingerprint=m.get("fingerprint"), archive=archive_to_place,
                               stage="archive_verification", error=str(exc))
                        print(f"DVD archive verification/metadata notice pending or failed: {exc}", file=sys.stderr)
                    else:
                        record(cfg, "playable_pending", fingerprint=m.get("fingerprint"), archive=archive_to_place, cause=str(exc))
                        print(f"NAS backup verified; EmuDeck copy pending/failed: {exc}", file=sys.stderr)
                    return 2
        else:
            drives = q.drive or [x["drive"] for x in list_drives()]
            previous = {}
            if q.execute:
                resume_pending_once(cfg)
            while True:
                for drive in drives:
                    try:
                        archive_to_place = None
                        with drive_lock(cfg, drive):
                            m = inspect(cfg, drive); key = str(drive)
                            signature = (m.get("fingerprint"), m.get("media_loaded"), bool(m.get("mounted_root")), m.get("disc_change_count"))
                            if key not in previous or previous[key] != signature:
                                previous[key] = signature
                                if q.execute and m.get("decision") == "suppressed":
                                    archive_to_place = latest_archive(cfg, m.get("fingerprint"))
                                elif q.execute and m.get("classification") == "ps3":
                                    dispatch_ps3(cfg, drive, m)
                                elif q.execute and m.get("classification") == "wii":
                                    archive_to_place = dispatch_wii(cfg, drive, m, q)
                                elif q.execute and m.get("classification") == "gamecube":
                                    archive_to_place = dispatch_gamecube(cfg, drive, m, q)
                                elif q.execute and m.get("classification") == "dvd_video":
                                    archive_to_place = dispatch_dvd(cfg, drive, m, q)
                                else:
                                    show_probe(cfg, drive, log=True, metadata=m)
                        if isinstance(archive_to_place, (str, os.PathLike)) and archive_to_place:
                            try:
                                if m.get("classification") == "dvd_video":
                                    finish_archive(cfg, archive_to_place, True)
                                else:
                                    place_and_notify(cfg, archive_to_place, True)
                            except Exception as exc:
                                if m.get("classification") == "dvd_video":
                                    record(cfg, "failed", fingerprint=m.get("fingerprint"), archive=archive_to_place,
                                           stage="archive_verification", error=str(exc))
                                    print(f"DVD archive verification/metadata notice pending or failed: {exc}", file=sys.stderr)
                                else:
                                    record(cfg, "playable_pending", fingerprint=m.get("fingerprint"), archive=archive_to_place, cause=str(exc))
                                    print(f"NAS backup verified; EmuDeck copy pending/failed: {exc}", file=sys.stderr)
                    except Exception as exc: print(f"{drive}: {exc}", file=sys.stderr)
                time.sleep(max(1.0, q.interval))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 2
    except KeyboardInterrupt:
        print("Foreground workflow stopped.", file=sys.stderr); return 130
    return 0

if __name__ == "__main__": raise SystemExit(main())
