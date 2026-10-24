"""Collect local, info-only MakeMKV metadata from a validated DVD drive."""
# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone

from portable_disc_version import program_stamp

MAX_LOG_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 300
VLC_TIMEOUT_SECONDS = 20
_DRIVE = re.compile(r"[A-Z]:\Z")
_EXE = re.compile(r"(?i)\.exe\Z")
_ATTRIBUTES = {
    2: "name", 8: "chapters", 9: "duration", 10: "size", 11: "size_alt",
    16: "source_file", 19: "video_size", 23: "datetime", 24: "source_title_id",
    25: "segment_count", 26: "segments", 32: "volume_name",
}


def build_info_argv(executable: str, drive: str) -> list[str]:
    """Build the fixed MakeMKV info command for a Windows drive letter."""
    if not isinstance(drive, str) or not _DRIVE.fullmatch(drive):
        raise ValueError("drive must be an uppercase Windows drive such as E:")
    if not isinstance(executable, str) or not executable or not _EXE.search(executable):
        raise ValueError("configured MakeMKV path must end in .exe")
    return [executable, "--robot", "--cache=1", "info", "dev:" + drive]


def _decode_value(value: str) -> str:
    if not (value.startswith('"') and value.endswith('"')):
        return value
    body = value[1:-1]
    out, i = [], 0
    escapes = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            i += 1
            out.append(escapes.get(body[i], "\\" + body[i]))
        else:
            out.append(body[i])
        i += 1
    return "".join(out)


def _csv_fields(value: str) -> list[str]:
    fields, start, quoted, i = [], 0, False, 0
    while i < len(value):
        char = value[i]
        if char == "\\" and quoted:
            i += 2
            continue
        if char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            fields.append(_decode_value(value[start:i]))
            start = i + 1
        i += 1
    if quoted:
        raise ValueError("unterminated quoted field")
    fields.append(_decode_value(value[start:]))
    return fields


def parse_robot(text: str) -> dict:
    records, diagnostics, titles = [], [], {}
    messages = []
    count = None
    shapes = {"CINFO": 3, "TINFO": 4, "SINFO": 5}
    for line_no, raw in enumerate(text.splitlines(), 1):
        if ":" not in raw:
            if raw:
                diagnostics.append({"line": line_no, "raw": raw, "issue": "missing record prefix"})
            continue
        prefix, payload = raw.split(":", 1)
        try:
            fields = _csv_fields(payload)
        except ValueError as exc:
            records.append({"prefix": prefix, "fields": [], "raw_line": raw, "shape": "malformed"})
            diagnostics.append({"line": line_no, "prefix": prefix, "issue": str(exc), "raw": raw})
            continue
        row = {"prefix": prefix, "fields": fields, "raw_line": raw}
        if prefix == "MSG":
            row["shape"] = "msg"
            valid = len(fields) >= 5
            try:
                code, flags, param_count = (int(fields[i]) for i in range(3))
                valid = valid and code >= 0 and flags >= 0 and param_count >= 0 and len(fields) == 5 + param_count
            except (IndexError, TypeError, ValueError):
                valid = False
                code = flags = param_count = None
            if valid:
                message = {"code": code, "flags": flags, "count": param_count,
                           "message": fields[3], "format": fields[4], "params": fields[5:],
                           "raw_fields": fields, "raw_line": raw}
                row["message"] = message
                messages.append(message)
                if code == 4004:
                    message["classification"] = "source_integrity_warning"
                else:
                    message["classification"] = "unclassified"
            else:
                row["shape"] = "unexpected"
                diagnostics.append({"line": line_no, "prefix": prefix,
                                    "issue": "invalid MSG schema; expected numeric code, flags, count and exactly count parameters",
                                    "raw": raw})
        elif prefix in {"TCOUT", "TCOUNT"}:
            row["shape"] = "count"
            if len(fields) == 1 and fields[0].isdigit():
                count = int(fields[0])
                row["count"] = count
            else:
                row["shape"] = "unexpected"
                diagnostics.append({"line": line_no, "prefix": prefix, "issue": "invalid count record", "raw": raw})
        elif prefix in shapes:
            expected = shapes[prefix]
            row["shape"] = f"{prefix.lower()}_{expected}_fields" if len(fields) == expected else "unexpected"
            if len(fields) != expected:
                diagnostics.append({"line": line_no, "prefix": prefix, "issue": f"expected {expected} fields, got {len(fields)}", "raw": raw})
            elif prefix in {"TINFO", "SINFO"}:
                idx_at = 0 if prefix == "TINFO" else 0
                try:
                    title_index = int(fields[idx_at])
                    attribute_id = int(fields[idx_at + (1 if prefix == "TINFO" else 2)])
                except ValueError:
                    row["shape"] = "unexpected"
                    diagnostics.append({"line": line_no, "prefix": prefix, "issue": "invalid numeric index or attribute id", "raw": raw})
                else:
                    candidate = {"attribute_id": attribute_id, "attribute": _ATTRIBUTES.get(attribute_id),
                                 "fields": fields, "raw_line": raw, "confidence": "tool-reported"}
                    row.update({"title_index": title_index, "candidate": candidate})
                    if prefix == "TINFO":
                        titles.setdefault(title_index, []).append(candidate)
        else:
            row["shape"] = "unknown_prefix"
            diagnostics.append({"line": line_no, "prefix": prefix, "issue": "unknown record prefix", "raw": raw})
        records.append(row)
    message_counts = {}
    for message in messages:
        key = str(message["code"])
        message_counts[key] = message_counts.get(key, 0) + 1
    source_warnings = [{"code": item["code"], "file": item["params"][0] if item["params"] else None,
                        "offset": item["params"][1] if len(item["params"]) > 1 else None}
                       for item in messages if item["code"] == 4004]
    return {"records": records, "titles": [{"title_index": index, "raw_attributes": attrs}
                                             for index, attrs in sorted(titles.items())],
            "title_count": count, "diagnostics": diagnostics, "messages": messages,
            "message_counts": message_counts, "source_integrity_warnings": source_warnings}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_log(path: Path, data: bytes) -> dict:
    saved = data[:MAX_LOG_BYTES]
    path.write_bytes(saved)
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
            "saved_sha256": hashlib.sha256(saved).hexdigest(),
            "bytes_saved": len(saved), "bytes_captured": len(data), "truncated": len(data) > len(saved)}


def inspect_vlc(cfg: dict, evidence_dir: str | os.PathLike) -> dict:
    """Collect bounded VLC version/help/module evidence without opening media."""
    root = Path(evidence_dir)
    root.mkdir(parents=True, exist_ok=False)
    report = {
        **program_stamp(), "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "incomplete", "metadata_only": True,
        "menu_opened": False, "capture_started": False,
        "routing": {"pwd_set_to_local_job_directory": True},
        "evidence_directory": str(root), "report_path": str(root / "report.json"),
        "help_scope": "core_only",
        "queries": {}, "options": {},
    }
    try:
        tools = cfg.get("tools", {}) if isinstance(cfg, dict) else {}
        configured = tools.get("vlc") if isinstance(tools, dict) else None
        if not isinstance(configured, str) or not configured.strip():
            raise ValueError("tools.vlc must name an installed VLC executable")
        executable = Path(configured).expanduser()
        if not executable.is_absolute() or executable.suffix.casefold() != ".exe" or not executable.is_file():
            raise ValueError("configured VLC path must be an existing absolute .exe path")
        executable = executable.resolve(strict=True)
        report["executable"] = str(executable)
        report["executable_bytes"] = executable.stat().st_size
        report["executable_sha256"] = _sha256(executable)
        child_env = os.environ.copy()
        child_env["PWD"] = str(root)
        base = [str(executable), "--no-crashdump", "--ignore-config", "--no-media-library", "--no-one-instance"]
        report["routing"]["cwd"] = str(root)
        report["base_argv"] = list(base)
        create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        queries = (("version", ("--version",)),
                   ("core_help", ("--advanced", "--help")),
                   ("modules", ("--list",)))
        for name, options in queries:
            argv = [*base, *options]
            stdout = stderr = b""
            returncode = None
            error = None
            try:
                result = subprocess.run(
                    argv, shell=False, capture_output=True, stdin=subprocess.DEVNULL,
                    timeout=VLC_TIMEOUT_SECONDS, env=child_env, cwd=str(root),
                    creationflags=create_no_window,
                    check=False,
                )
                stdout, stderr, returncode = result.stdout or b"", result.stderr or b"", result.returncode
            except subprocess.TimeoutExpired as exc:
                stdout, stderr = exc.stdout or b"", exc.stderr or b""
                error = f"timed out after {VLC_TIMEOUT_SECONDS} seconds"
            except OSError as exc:
                error = f"{type(exc).__name__}: {exc}"
            out_log = _write_log(root / f"{name}-stdout.log", stdout)
            err_log = _write_log(root / f"{name}-stderr.log", stderr)
            report["queries"][name] = {
                "argv": argv, "timeout_seconds": VLC_TIMEOUT_SECONDS, "returncode": returncode,
                "error": error, "stdout": out_log, "stderr": err_log,
                "stdout_nonempty": bool(stdout.strip()), "stderr_nonempty": bool(stderr.strip()),
            }
        version_text = "\n".join(
            (root / f"version-{stream}.log").read_bytes().decode("ascii", errors="replace")
            for stream in ("stdout", "stderr"))
        match = re.search(r"(?i)\bVLC\s+(?:media\s+player|version)\s+(\d+\.\d+\.\d+)\b", version_text)
        report["vlc_version"] = match.group(1) if match else "unknown"
        core_help_text = "\n".join(
            (root / f"core_help-{stream}.log").read_bytes().decode("utf-8", errors="replace")
            for stream in ("stdout", "stderr"))
        tokens = ("--no-audio", "--no-crashdump", "--ignore-config", "--no-media-library",
                  "--no-one-instance", "--audio", "--one-instance", "--run-time", "--start-paused")
        report["options"] = {token: ("observed" if re.search(r"(?<![\w-])" + re.escape(token) + r"(?![\w-])", core_help_text) else "not_observed")
                              for token in tokens}
        module_text = (root / "modules-stdout.log").read_bytes().decode("utf-8", errors="replace")
        report["module_availability_evidence"] = {
            name: ("listed" if re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", module_text, re.IGNORECASE)
                   else "not_listed")
            for name in ("dvdnav", "dvdread", "qt")
        }
        required = ("core_help", "modules")
        complete = all(report["queries"][name]["returncode"] == 0
                       and report["queries"][name]["stdout_nonempty"]
                       and report["queries"][name]["error"] is None for name in required)
        complete = complete and report["queries"]["version"]["returncode"] == 0
        complete = complete and report["queries"]["version"]["error"] is None and match is not None
        report["status"] = "complete" if complete else "incomplete"
        report["capability_limits"] = [
            "listed modules are availability evidence only; they do not prove disc behavior",
            "module names are reported as listed or not listed only",
            "not_observed options are not proof that VLC lacks those options",
            "this query did not open a menu, read a disc, or start capture",
        ]
    except (OSError, ValueError, TypeError) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    with (root / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return report


def inspect_dvd(cfg: dict, drive: str, metadata: dict, evidence_dir: str | os.PathLike) -> dict:
    """Run one bounded, info-only MakeMKV query and persist local evidence."""
    root = Path(evidence_dir)
    root.mkdir(parents=True, exist_ok=False)
    argv, exe_hash, error = None, None, None
    stdout = stderr = b""
    exit_code = None
    try:
        executable = cfg.get("tools", {}).get("makemkv")
        argv = build_info_argv(executable, drive)
        exe_path = Path(executable)
        if not _EXE.search(executable) or not exe_path.is_file():
            raise FileNotFoundError("configured MakeMKV executable does not exist")
        exe_hash = _sha256(exe_path)
        result = subprocess.run(argv, shell=False, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
        stdout, stderr, exit_code = result.stdout or b"", result.stderr or b"", result.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        error = f"MakeMKV info timed out after {TIMEOUT_SECONDS} seconds"
    except (OSError, ValueError, TypeError) as exc:
        error = str(exc)
    out_log = _write_log(root / "stdout.log", stdout)
    err_log = _write_log(root / "stderr.log", stderr)
    decoded = stdout.decode("utf-8", errors="replace")
    parsed = parse_robot(decoded)
    has_info = any(row.get("prefix") in {"CINFO", "TINFO", "SINFO"}
                   and row.get("shape") != "unexpected" and row.get("shape") != "malformed"
                   for row in parsed["records"])
    blockers = []
    for key in ("title", "year", "content_kind"):
        if not metadata.get(key):
            blockers.append(f"verified {key} is unknown")
    if not metadata.get("content_kind"):
        blockers.append("episode mapping is unknown if the disc is television content")
    blockers.append("this metadata-only query does not attempt preservation or verified named video filing")
    if error:
        blockers.append(error)
    if exit_code != 0:
        blockers.append(f"MakeMKV exited with status {exit_code}")
    if parsed["title_count"] is None or parsed["title_count"] < 1:
        blockers.append("MakeMKV reported no positive title count")
    if not has_info:
        blockers.append("MakeMKV returned no recognized metadata records")
    if parsed["source_integrity_warnings"]:
        blockers.append(f"MakeMKV reported {len(parsed['source_integrity_warnings'])} source-integrity warning(s); retain this evidence and assess actual preservation reads separately")
    result_status = "metadata_collected" if not error and exit_code == 0 and parsed["title_count"] and parsed["title_count"] > 0 and has_info else "failed"
    report = {
        **program_stamp(), "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": result_status, "mode": "info-only", "drive": drive,
        "argv": argv, "executable_sha256": exe_hash, "exit_code": exit_code,
        "logs": {"stdout": out_log, "stderr": err_log},
        "stdout_sha256": out_log["sha256"], "stderr_sha256": err_log["sha256"],
        "robot": parsed, "blockers": blockers, "preservation_blockers": [],
        "unknowns": ["title", "year", "content_kind", "episode"],
        "metadata": {**metadata, "source_integrity": "warnings_reported" if parsed["source_integrity_warnings"] else "not_reported"},
    }
    with (root / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return report


def build_archive_info_argv(executable: str, iso_path: str | os.PathLike) -> list[str]:
    """Build fixed MakeMKV information arguments for one verified ISO."""
    if not isinstance(executable, str) or not executable or not _EXE.search(executable):
        raise ValueError("configured MakeMKV path must end in .exe")
    if not isinstance(iso_path, (str, os.PathLike)) or not os.path.isabs(iso_path):
        raise ValueError("verified ISO path must be absolute")
    return [executable, "--robot", "--noscan", "--cache=1", "--minlength=0", "info", "iso:" + os.fspath(iso_path)]


def inspect_archive(cfg: dict, archive_info: dict, evidence_dir: str | os.PathLike) -> dict:
    """Run one bounded MakeMKV information query on a validated archive ISO."""
    root = Path(evidence_dir).resolve()
    root.mkdir(parents=True, exist_ok=False)
    source = archive_info if isinstance(archive_info, dict) else {}
    argv, exe_hash, error = None, None, None
    stdout = stderr = b""
    exit_code = None
    try:
        iso_path = source.get("iso_path")
        expected_hash = source.get("iso_sha256")
        if not isinstance(iso_path, str) or not os.path.isabs(iso_path):
            raise ValueError("verified archive source lacks an absolute ISO path")
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
            raise ValueError("verified archive source lacks a valid ISO SHA256")
        iso_file = Path(iso_path)
        if not iso_file.is_file():
            raise ValueError("verified archive ISO is absent")
        expected_bytes = source.get("iso_bytes")
        if not isinstance(expected_bytes, int) or expected_bytes < 0 or iso_file.stat().st_size != expected_bytes:
            raise ValueError("verified archive ISO size changed")
        executable = cfg.get("tools", {}).get("makemkv")
        argv = build_archive_info_argv(executable, iso_path)
        exe_path = Path(executable)
        if not exe_path.is_file():
            raise FileNotFoundError("configured MakeMKV executable does not exist")
        exe_hash = _sha256(exe_path)
        result = subprocess.run(
            argv, shell=False, capture_output=True, stdin=subprocess.DEVNULL,
            timeout=TIMEOUT_SECONDS, check=False, cwd=str(root),
        )
        stdout, stderr, exit_code = result.stdout or b"", result.stderr or b"", result.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        error = f"MakeMKV archive info timed out after {TIMEOUT_SECONDS} seconds"
    except (OSError, ValueError, TypeError) as exc:
        error = str(exc)

    out_log = _write_log(root / "stdout.log", stdout)
    err_log = _write_log(root / "stderr.log", stderr)
    parsed = parse_robot(stdout.decode("utf-8", errors="replace"))
    title_ids = [item["title_index"] for item in parsed["titles"]]
    count_records = [row for row in parsed["records"] if row.get("prefix") in {"TCOUNT", "TCOUT"}]
    info_ids = {row.get("title_index") for row in parsed["records"]
                if row.get("prefix") == "TINFO" and row.get("shape") == "tinfo_4_fields"}
    stream_ids = {row.get("title_index") for row in parsed["records"]
                  if row.get("prefix") == "SINFO" and row.get("shape") == "sinfo_5_fields"}
    required_bad = [row for row in parsed["records"]
                    if row.get("prefix") in {"TCOUNT", "TCOUT", "TINFO", "SINFO", "MSG"}
                    and row.get("shape") in {"unexpected", "malformed"}]
    expected_ids = set(title_ids)
    title_ids_coherent = (parsed["title_count"] is not None and parsed["title_count"] > 0
                         and len(expected_ids) == parsed["title_count"]
                         and all(0 <= index < parsed["title_count"] for index in expected_ids))
    titles_usable = (
        len(count_records) == 1 and title_ids_coherent
        and expected_ids <= info_ids
        and expected_ids <= stream_ids and not required_bad
    )
    success_message = any(item["code"] == 5011 and item["flags"] == 0 for item in parsed["messages"])
    blockers = []
    if error:
        blockers.append(error)
    if exit_code != 0:
        blockers.append(f"MakeMKV exited with status {exit_code}")
    if not titles_usable:
        blockers.append("MakeMKV archive response lacks a coherent title and stream list with recognized required records")
    if not success_message:
        blockers.append("MakeMKV returned no observed successful-operation message")
    report = {
        **program_stamp(), "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "archive_inspected" if not error and exit_code == 0 and titles_usable and success_message else "incomplete",
        "mode": "archive-info-only", "argv": argv, "executable_sha256": exe_hash,
        "exit_code": exit_code, "timeout_seconds": TIMEOUT_SECONDS,
        "source_info": {key: source.get(key) for key in
                        ("archive", "iso_path", "iso_sha256", "iso_bytes", "records_digest", "fingerprint", "marker_sha256")},
        "robot": parsed, "blockers": blockers,
        "unknowns": ["release title", "year", "content kind", "episode mapping", "decryption", "playability"],
        "title_list": parsed["titles"], "source_integrity_warnings": parsed["source_integrity_warnings"],
        "prior_inspection_references": source.get("metadata", {}).get("metadata_query_evidence", []),
        "logs": {"stdout": out_log, "stderr": err_log},
        "stdout_sha256": out_log["sha256"], "stderr_sha256": err_log["sha256"],
    }
    with (root / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return report
