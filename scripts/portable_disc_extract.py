"""Extract and verify titles from a previously verified DVD archive."""
# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
from datetime import datetime, timezone
from fractions import Fraction

from portable_disc_version import program_stamp
from portable_disc_video import parse_robot

EXTRACT_TIMEOUT = 4 * 60 * 60
PROBE_TIMEOUT = 120
DECODE_TIMEOUT = 60 * 60
PACKET_TIMEOUT = 60 * 60
FRAME_MAX_BYTES = 2 * 1024 * 1024
SAFETY_BYTES = 256 * 1024 * 1024
CODECS = {
    "V_MPEG2": ("video", "mpeg2video"), "A_AC3": ("audio", "ac3"),
    "A_MPEG/L2": ("audio", "mp2"), "A_DTS": ("audio", "dts"),
    "A_PCM/INT/LIT": ("audio", "pcm_s16le"), "S_VOBSUB": ("subtitle", "dvd_subtitle"),
}


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tool(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError(f"configured {name} executable is missing")
    path = Path(value).expanduser()
    if not path.is_absolute() or path.suffix.casefold() != ".exe" or not path.is_file():
        raise ValueError(f"configured {name} path must be an existing absolute .exe path")
    path = path.resolve(strict=True)
    return path, _sha256(path)


def _records(inspection, prefix, title_id=None, attribute=None):
    for row in inspection["robot"]["records"]:
        fields = row.get("fields", [])
        if row.get("prefix") != prefix or len(fields) != (4 if prefix == "TINFO" else 5):
            continue
        if title_id is not None and fields[0] != str(title_id):
            continue
        if attribute is not None and fields[1 if prefix == "TINFO" else 2] != str(attribute):
            continue
        yield fields


def _title_map(inspection):
    titles = {}
    for fields in _records(inspection, "TINFO", attribute=27):
        title_id, filename = int(fields[0]), fields[3]
        stem = filename.split(".", 1)[0].upper()
        if (not filename or any(ord(char) < 32 or char in '<>:"/\\|?*' for char in filename)
                or filename.endswith((".", " ")) or stem in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9]", stem)
                or Path(filename).name != filename or Path(filename).suffix.casefold() != ".mkv"):
            raise ValueError(f"unsafe MakeMKV output filename for title {title_id}")
        if title_id in titles:
            raise ValueError(f"duplicate output filename record for title {title_id}")
        titles[title_id] = filename
    count = inspection["robot"]["title_count"]
    ids = sorted(titles)
    if count < 1 or len(ids) != count or ids[0] != 0 or ids[-1] != count - 1 or len({name.casefold() for name in titles.values()}) != count:
        raise ValueError("inspection lacks one unique TINFO attribute 27 filename per title")
    return titles


def plan_extract(cfg, source, inspection, job: Path) -> dict:
    """Return a dry plan. Do not create files or run tools."""
    plan = {"ready": False, "blockers": [], "job_dir": str(job)}
    try:
        if not isinstance(source, dict) or not isinstance(inspection, dict):
            raise ValueError("verified source and saved inspection must be objects")
        if inspection.get("status") != "archive_inspected" or inspection.get("exit_code") != 0:
            raise ValueError("saved inspection is not a successful archive inspection")
        source_info = inspection.get("source_info", {})
        for key in ("archive", "iso_path", "iso_sha256", "iso_bytes", "records_digest", "fingerprint", "marker_sha256"):
            if source_info.get(key) != source.get(key):
                raise ValueError(f"saved inspection does not match verified source field {key}")
        iso_path = source.get("iso_path")
        iso = Path(iso_path) if isinstance(iso_path, str) else None
        if not iso or not iso.is_absolute():
            raise ValueError("verified ISO path must be absolute")
        if not iso.is_file() or iso.stat().st_size != source.get("iso_bytes"):
            raise ValueError("verified archive ISO is absent or its size changed")
        titles = _title_map(inspection)
        tools = cfg.get("tools", {})
        paths, hashes = {}, {}
        for name in ("makemkv", "ffprobe", "ffmpeg"):
            paths[name], hashes[name] = _tool(tools.get(name), name)
        job_path = Path(job).expanduser().absolute()
        if job_path.exists() or job_path.is_symlink() or str(job_path).startswith("\\\\"):
            raise ValueError("job path must be new and local")
        free = shutil.disk_usage(job_path.parent).free
        sizes = {}
        duplicate_sizes = False
        for fields in _records(inspection, "TINFO", attribute=11):
            try:
                if fields[0] in sizes:
                    duplicate_sizes = True
                sizes[fields[0]] = int(fields[3])
            except ValueError:
                duplicate_sizes = True
        estimate = (sum(sizes.values()) if not duplicate_sizes and set(sizes) == {str(key) for key in titles}
                    else int(source["iso_bytes"]))
        required = estimate + max(SAFETY_BYTES, estimate // 10)
        if free < required:
            raise ValueError(f"local output volume lacks space: need {required} bytes, have {free}")
        plan.update({"ready": True, "blockers": [], "job_dir": str(job_path),
                     "output_dir": str(job_path / "output"), "source": source,
                     "inspection": inspection, "title_map": titles,
                     "tools": {key: str(value) for key, value in paths.items()},
                     "tool_sha256": hashes, "expected_bytes": estimate,
                     "required_free_bytes": required, "title_count": len(titles)})
    except (OSError, ValueError, TypeError, KeyError) as exc:
        plan["blockers"].append(str(exc))
    return plan


def _run(argv, timeout, cwd):
    return subprocess.run(argv, shell=False, capture_output=True, stdin=subprocess.DEVNULL,
                          timeout=timeout, check=False, cwd=str(cwd))


def _successful(stdout):
    parsed = parse_robot(stdout.decode("utf-8", errors="replace"))
    return any(message.get("code") == 5011 and message.get("flags") == 0
               for message in parsed["messages"])


def _is_reparse(path):
    if path.is_symlink():
        return True
    try:
        return bool(path.lstat().st_file_attributes & 0x400)
    except (AttributeError, OSError):
        return False


def _publish_neutral(source, target):
    before = _sha256(source)
    os.link(source, target)
    after_target = _sha256(target)
    if before != after_target:
        raise ValueError("neutral title copy does not match unchanged MakeMKV output")
    return after_target


def _source_streams(inspection, title_id):
    streams = {}
    for fields in _records(inspection, "SINFO", title_id):
        stream = streams.setdefault(fields[1], {})
        if fields[2] == "1":
            stream["type"] = fields[4]
        elif fields[2] == "5":
            stream["codec_id"] = fields[4]
    return streams


def _duration(inspection, title_id):
    for fields in _records(inspection, "TINFO", title_id, 9):
        match = re.fullmatch(r"(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)", fields[3])
        if match:
            hours, minutes, seconds = match.groups()
            return int(hours or 0) * 3600 + int(minutes) * 60 + float(seconds)
    return None


def _local_path(value, label):
    if not isinstance(value, str) or not value or value.startswith("\\\\"):
        raise ValueError(f"{label} must be an absolute local path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute local path")
    return path.resolve(strict=True)


def _packet_time(value):
    if value in (None, "", "N/A"):
        raise ValueError("packet scan lacks a numeric timestamp or duration")
    return Fraction(value)


def _packet_scan(path, log_path, tool, cwd):
    argv = [tool, "-v", "error", "-show_packets", "-show_entries",
            "packet=stream_index,pts_time,duration_time,size",
            "-of", "compact=p=0:nk=0", str(path)]
    with log_path.open("xb") as stdout:
        result = subprocess.run(argv, shell=False, stdout=stdout, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, timeout=PACKET_TIMEOUT,
                                check=False, cwd=str(cwd))
    return argv, result


def _aggregate_packets(path, selected_streams):
    streams = {}
    with path.open("r", encoding="utf-8", errors="strict") as packet_log:
        for line_number, line in enumerate(packet_log, 1):
            fields = {}
            for pair in line.rstrip("\r\n").split("|"):
                if "=" not in pair:
                    raise ValueError(f"packet scan has malformed line {line_number}")
                key, value = pair.split("=", 1)
                fields[key] = value
            try:
                stream_index = int(fields["stream_index"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"packet scan lacks a stream index on line {line_number}") from exc
            if stream_index not in selected_streams:
                continue
            try:
                pts = _packet_time(fields.get("pts_time"))
                duration = _packet_time(fields.get("duration_time"))
                size = int(fields["size"])
            except (KeyError, TypeError, ValueError, ZeroDivisionError) as exc:
                raise ValueError(f"packet scan has incomplete numeric data on line {line_number}") from exc
            if stream_index < 0 or duration <= 0 or size <= 0:
                raise ValueError(f"packet scan has invalid values on line {line_number}")
            stat = streams.setdefault(stream_index, {"packet_count": 0, "byte_count": 0,
                "first_pts": pts, "max_pts": pts, "end_pts": pts + duration,
                "max_packet_duration": duration, "pts_precision": Fraction(0),
                "duration_precision": Fraction(0)})
            stat["packet_count"] += 1
            stat["byte_count"] += size
            stat["first_pts"] = min(stat["first_pts"], pts)
            stat["max_pts"] = max(stat["max_pts"], pts)
            stat["end_pts"] = max(stat["end_pts"], pts + duration)
            stat["max_packet_duration"] = max(stat["max_packet_duration"], duration)
            for key, field in (("pts_precision", "pts_time"), ("duration_precision", "duration_time")):
                text = fields[field]
                decimal_places = len(text.partition(".")[2]) if "." in text else 0
                stat[key] = max(stat[key], Fraction(1, 10 ** decimal_places))
    return streams


def _stream_tag(stream, name):
    tags = stream.get("tags", {})
    matches = [(key, value) for key, value in tags.items()
               if key.upper() == name or key.upper().startswith(name + "-")]
    if len(matches) > 1:
        raise ValueError(f"audio/video stream has ambiguous {name} tags")
    return matches[0][1] if matches else None


def _stream_duration_tag(stream):
    value = _stream_tag(stream, "DURATION")
    if value is None:
        raise ValueError("audio/video stream lacks a duration tag")
    match = re.fullmatch(r"(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)", str(value))
    if not match:
        raise ValueError("stream duration tag is not numeric")
    hours, minutes, seconds = match.groups()
    return Fraction(int(hours or 0) * 3600 + int(minutes) * 60) + Fraction(seconds)


def _optional_count_tag(stream, name):
    value = _stream_tag(stream, name)
    if value is None:
        return None
    try:
        count = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"stream {name} tag is not an integer") from exc
    if count < 0:
        raise ValueError(f"stream {name} tag is negative")
    return count


def _verify_title(plan, item, neutral, job, report):
    title_id = item["title_id"]
    before_hash = _sha256(neutral)
    if item.get("sha256") and before_hash != item["sha256"]:
        raise ValueError("title hash differs from the saved native-output hash")
    probe_argv = [plan["tools"]["ffprobe"], "-v", "error", "-count_packets", "-count_frames",
                  "-show_streams", "-show_format", "-of", "json", str(neutral)]
    probe = _run(probe_argv, PROBE_TIMEOUT, job)
    probe_stdout = probe.stdout or b""
    probe_stderr = probe.stderr or b""
    probe_out = job / f"ffprobe-title-{title_id:03}.stdout.log"
    probe_err = job / f"ffprobe-title-{title_id:03}.stderr.log"
    probe_out.write_bytes(probe_stdout)
    probe_err.write_bytes(probe_stderr)
    item["ffprobe_argv"] = probe_argv
    item["ffprobe_returncode"] = probe.returncode
    item["logs"][probe_out.name] = {"path": str(probe_out), "bytes": len(probe_stdout),
                                     "sha256": hashlib.sha256(probe_stdout).hexdigest()}
    item["logs"][probe_err.name] = {"path": str(probe_err), "bytes": len(probe_stderr),
                                     "sha256": hashlib.sha256(probe_stderr).hexdigest()}
    if probe.returncode != 0 or probe_stderr.strip():
        raise ValueError("ffprobe failed or reported errors")
    data = json.loads(probe_stdout.decode("utf-8"))
    streams = data.get("streams")
    if not isinstance(streams, list) or not streams:
        raise ValueError("ffprobe found no streams")
    if any(stream.get("codec_type") not in {"video", "audio", "subtitle"} for stream in streams):
        raise ValueError("output has an unexpected stream type")
    source_streams = item["source_streams"]
    source_av = [stream for stream in source_streams.values() if stream.get("type") in {"Video", "Audio"}]
    actual_av = [stream for stream in streams if stream.get("codec_type") in {"video", "audio"}]
    expected = [CODECS.get(stream.get("codec_id")) for stream in source_av]
    actual = [(stream.get("codec_type"), stream.get("codec_name")) for stream in actual_av]
    if None in expected or Counter(actual) - Counter(expected):
        raise ValueError("output audio/video codecs exceed or differ from the recognized source inventory")
    if not any(kind == "video" for kind, _codec in actual):
        raise ValueError("output has no video stream")
    if any(stream.get("type") == "Audio" for stream in source_av) and not any(kind == "audio" for kind, _codec in actual):
        raise ValueError("output omits all source audio streams")
    if len(actual) < len(expected):
        report["omissions"].append({"title_id": title_id,
            "reason": "source audio/video streams omitted by default selection",
            "source_streams": source_av, "output_streams": actual})
    if "matroska" not in str(data.get("format", {}).get("format_name", "")).split(","):
        raise ValueError("ffprobe did not identify a Matroska container")
    with neutral.open("rb") as stream:
        if stream.read(4) != bytes.fromhex("1a45dfa3"):
            raise ValueError("output lacks the EBML container header")
    source_duration = _duration(plan["inspection"], title_id) if plan.get("inspection") else None
    format_duration = float(data.get("format", {}).get("duration", 0) or 0)
    item["duration_diagnostic"] = {"source_tinfo_seconds": source_duration,
        "container_seconds": format_duration,
        "difference_seconds": (format_duration - source_duration) if source_duration is not None else None,
        "source_duration_cause": "unknown; retained as diagnostic, not a completeness gate"}
    source_subs = [stream for stream in source_streams.values() if stream.get("type") == "Subtitles"]
    output_subs = [(stream.get("codec_type"), stream.get("codec_name")) for stream in streams
                   if stream.get("codec_type") == "subtitle"]
    recognized_subs = [CODECS.get(stream.get("codec_id")) for stream in source_subs]
    recognized_subs = [codec for codec in recognized_subs if codec is not None]
    matched_subs = Counter(output_subs) & Counter(recognized_subs)
    unknown_source_subs = [stream for stream in source_subs if CODECS.get(stream.get("codec_id")) is None]
    unmatched_output_subs = Counter(output_subs) - Counter(recognized_subs)
    item["subtitle_coverage"] = {"rendering": "unverified", "source_streams": source_subs,
        "output_streams": output_subs, "matched_known_streams": list(matched_subs.elements()),
        "unknown_source_streams": unknown_source_subs,
        "unmapped_output_codecs": list(unmatched_output_subs.elements())}
    if unknown_source_subs or unmatched_output_subs or matched_subs != Counter(recognized_subs):
        report["omissions"].append({"title_id": title_id,
            "reason": "subtitle coverage is partial or unknown; subtitle rendering is unverified",
            **item["subtitle_coverage"]})
    packet_log = job / f"ffprobe-title-{title_id:03}.packets.log"
    packet_argv, packet_result = _packet_scan(neutral, packet_log, plan["tools"]["ffprobe"], job)
    packet_stderr = packet_result.stderr or b""
    packet_err = job / f"ffprobe-title-{title_id:03}.packets.stderr.log"
    packet_err.write_bytes(packet_stderr)
    item["packet_scan_argv"] = packet_argv
    item["packet_scan_returncode"] = packet_result.returncode
    item["logs"][packet_log.name] = {"path": str(packet_log), "bytes": packet_log.stat().st_size,
                                     "sha256": _sha256(packet_log)}
    item["logs"][packet_err.name] = {"path": str(packet_err), "bytes": len(packet_stderr),
                                     "sha256": hashlib.sha256(packet_stderr).hexdigest()}
    if packet_result.returncode != 0 or packet_stderr.strip():
        raise ValueError("ffprobe packet scan failed or reported errors")
    av_streams = [stream for stream in streams if stream.get("codec_type") in {"video", "audio"}]
    av_indices = {stream.get("index") for stream in av_streams if isinstance(stream.get("index"), int)}
    packet_stats = _aggregate_packets(packet_log, av_indices)
    coverage, frame_sum = [], 0
    for stream in av_streams:
        index = stream.get("index")
        if not isinstance(index, int) or index not in packet_stats:
            raise ValueError("audio/video stream lacks packet coverage")
        stats = packet_stats[index]
        try:
            packet_count = int(stream["nb_read_packets"])
            frame_count = int(stream["nb_read_frames"])
            time_base = Fraction(stream["time_base"])
        except (KeyError, TypeError, ValueError, ZeroDivisionError) as exc:
            raise ValueError("audio/video stream lacks numeric packet, frame, or time-base statistics") from exc
        if packet_count <= 0 or packet_count != stats["packet_count"] or frame_count <= 0 or time_base <= 0:
            raise ValueError("audio/video packet count or decoded frame count is incomplete")
        tag_duration = _stream_duration_tag(stream)
        makemkv_frames = _optional_count_tag(stream, "NUMBER_OF_FRAMES")
        makemkv_bytes = _optional_count_tag(stream, "NUMBER_OF_BYTES")
        if makemkv_frames is not None and makemkv_frames != stats["packet_count"]:
            raise ValueError("packet count differs from the per-stream MakeMKV frame count")
        if makemkv_bytes is not None and makemkv_bytes != stats["byte_count"]:
            raise ValueError("packet payload bytes differ from the per-stream MakeMKV byte count")
        span = stats["end_pts"] - stats["first_pts"]
        tolerance = stats["max_packet_duration"] + time_base + stats["pts_precision"] + stats["duration_precision"]
        if span <= 0 or abs(tag_duration - span) > tolerance:
            raise ValueError("audio/video packet PTS span does not cover the stream duration tag")
        coverage.append({"stream_index": index, "packet_count": stats["packet_count"],
            "ffprobe_packet_count": packet_count, "byte_count": stats["byte_count"],
            "first_pts_seconds": float(stats["first_pts"]), "max_pts_seconds": float(stats["max_pts"]),
            "packet_end_seconds": float(stats["end_pts"]), "packet_span_seconds": float(span),
            "stream_duration_tag_seconds": float(tag_duration), "tolerance_seconds": float(tolerance),
            "decoded_frame_count": frame_count, "time_base": str(time_base),
            "makemkv_number_of_frames": makemkv_frames,
            "makemkv_number_of_bytes": makemkv_bytes,
            "native_writer_baseline_limit": "per-stream MakeMKV output tags do not prove original-DVD frame completeness"})
        if stream.get("codec_type") == "video":
            frame_sum += frame_count
    if not coverage or not any(stream.get("codec_type") == "video" for stream in av_streams):
        raise ValueError("packet coverage lacks audio/video streams")
    item["packet_coverage"] = coverage
    item["decoded_frame_count"] = frame_sum
    item["native_writer_baseline"] = {"streams": coverage,
        "limits": "MakeMKV per-stream tags describe its output, not original-DVD semantic completeness"}
    item["ffprobe"] = {"stream_count": len(streams), "streams": [
        {"codec_type": stream.get("codec_type"), "codec_name": stream.get("codec_name")} for stream in streams],
        "duration_seconds": format_duration}
    decode_argv = [plan["tools"]["ffmpeg"], "-nostdin", "-v", "error", "-xerror", "-copyts",
                   "-i", str(neutral), "-map", "0:v?", "-map", "0:a?",
                   "-fps_mode:v", "passthrough", "-enc_time_base:v", "demux", "-f", "null", "-"]
    decoded = _run(decode_argv, DECODE_TIMEOUT, job)
    decode_stdout, decode_stderr = decoded.stdout or b"", decoded.stderr or b""
    stdout_log = job / f"ffmpeg-title-{title_id:03}.stdout.log"
    stderr_log = job / f"ffmpeg-title-{title_id:03}.stderr.log"
    stdout_log.write_bytes(decode_stdout)
    stderr_log.write_bytes(decode_stderr)
    item["decode_argv"] = decode_argv
    item["decode_returncode"] = decoded.returncode
    item["logs"][stdout_log.name] = {"path": str(stdout_log), "bytes": len(decode_stdout),
                                     "sha256": hashlib.sha256(decode_stdout).hexdigest()}
    item["logs"][stderr_log.name] = {"path": str(stderr_log), "bytes": len(decode_stderr),
                                     "sha256": hashlib.sha256(decode_stderr).hexdigest()}
    if _sha256(neutral) != before_hash:
        raise ValueError("title changed during verification")
    if decoded.returncode != 0 or decode_stderr.strip():
        if b"non monotonically increasing dts" in decode_stderr.lower() or b"non-monotonous dts" in decode_stderr.lower():
            item["decode_diagnostic"] = "NULL-muxer DTS monotonicity error; diagnostic only, decode remains incomplete"
        raise ValueError("strict full audio/video decode failed or reported errors")
    item["decoded_audio_video"] = True
    item["status"] = "verified"


def _write_json(path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def extract_archive(plan) -> dict:
    """Extract and verify all titles. Keep all evidence in the local job."""
    job = Path(plan["job_dir"])
    job.mkdir(parents=True, exist_ok=False)
    output = job / "output"
    output.mkdir(exist_ok=False)
    report = {**program_stamp(), "created_utc": datetime.now(timezone.utc).isoformat(),
              "status": "derivatives_incomplete", "title_count": plan["title_count"],
              "verified_title_count": 0,
              "stream_selection_contract": "All reported titles requested; MakeMKV default stream selection; stream and angle coverage is not complete by guarantee.",
              "subtitle_rendering": "unverified",
              "blockers": [], "omissions": [], "titles": [], "logs": {},
              "source_integrity_warnings": plan["inspection"].get("source_integrity_warnings", []),
              "source": {key: plan["source"].get(key) for key in
                         ("archive", "iso_path", "iso_sha256", "iso_bytes", "records_digest", "fingerprint", "marker_sha256")},
              "inspection_input": plan["inspection"].get("inspection_input"), "tool_sha256": plan["tool_sha256"]}
    argv = [plan["tools"]["makemkv"], "--robot", "--noscan", "--cache=512", "--minlength=0",
            "mkv", "iso:" + plan["source"]["iso_path"], "all", str(output)]
    report["argv"] = argv
    stdout = stderr = b""
    try:
        result = _run(argv, EXTRACT_TIMEOUT, job)
        stdout, stderr = result.stdout or b"", result.stderr or b""
        report["exit_code"] = result.returncode
        report["success_message_5011"] = _successful(stdout)
        if result.returncode != 0 or not report["success_message_5011"]:
            report["blockers"].append("MakeMKV did not report successful completion with exit status zero")
    except (OSError, subprocess.TimeoutExpired) as exc:
        stdout, stderr = getattr(exc, "stdout", None) or b"", getattr(exc, "stderr", None) or b""
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["blockers"].append("MakeMKV extraction failed or timed out")
    for name, data in (("makemkv-stdout.log", stdout), ("makemkv-stderr.log", stderr)):
        path = job / name
        path.write_bytes(data)
        report["logs"][name] = {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if report["blockers"]:
        _write_json(job / "report.json", report)
        return report
    if _is_reparse(output):
        report["blockers"].append("MakeMKV output directory became a reparse point")
        _write_json(job / "report.json", report)
        return report
    title_dir = job / "titles"
    title_dir.mkdir(exist_ok=False)
    actual_outputs = list(output.iterdir())
    expected_names = {name.casefold() for name in plan["title_map"].values()}
    if any(_is_reparse(path) or path.is_dir() or not path.is_file() for path in actual_outputs):
        report["blockers"].append("MakeMKV output contains a directory or reparse point")
    if {path.name.casefold() for path in actual_outputs} != expected_names:
        report["blockers"].append("MakeMKV output filenames do not match the complete TINFO attribute 27 map")
    for title_id, filename in sorted(plan["title_map"].items()):
        path = output / filename
        neutral = title_dir / f"title-{title_id:03}.mkv"
        item = {"title_id": title_id, "filename": filename,
                "source_streams": _source_streams(plan["inspection"], title_id), "logs": {}}
        try:
            if _is_reparse(path) or not path.is_file() or path.stat().st_size <= 0:
                raise ValueError("expected title output is absent, empty, or a reparse point")
            neutral_hash = _publish_neutral(path, neutral)
            item.update({"bytes": neutral.stat().st_size, "sha256": neutral_hash,
                         "path": str(neutral), "makemkv_filename": filename})
            _verify_title(plan, item, neutral, job, report)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            item["status"] = "incomplete"
            item["error"] = str(exc)
            report["blockers"].append(f"title {title_id}: {exc}")
        report["titles"].append(item)
    report["verified_title_count"] = sum(item.get("status") == "verified" for item in report["titles"])
    report["status"] = ("derivatives_inspected" if not report["blockers"]
                        and report["verified_title_count"] == report["title_count"] else "derivatives_incomplete")
    _write_json(job / "report.json", report)
    return report


def verify_existing(plan, receipt_dir) -> dict:
    """Verify saved local derivatives without reading the archive or extracting titles."""
    if not isinstance(plan, dict) or plan.get("ready") is not True:
        raise ValueError("recheck plan is not ready")
    old_job = _local_path(plan.get("old_job"), "old job")
    receipt = Path(receipt_dir).expanduser().absolute()
    if str(receipt).startswith("\\\\") or receipt.exists() or receipt.is_symlink():
        raise ValueError("receipt directory must be new and local")
    titles = plan.get("titles")
    if not isinstance(titles, list) or plan.get("title_count") != len(titles) or not titles:
        raise ValueError("recheck plan does not contain the full title set")
    for key in ("old_result_sha256", "old_native_log_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(plan.get(key, ""))):
            raise ValueError(f"saved {key} is missing or malformed")
    tools = {}
    for name in ("ffprobe", "ffmpeg"):
        tool_path, actual_hash = _tool(plan.get("tools", {}).get(name), name)
        if actual_hash != plan.get("tool_sha256", {}).get(name):
            raise ValueError(f"configured {name} hash changed")
        tools[name] = str(tool_path)
    normalized = []
    for expected_id, title in enumerate(titles):
        if not isinstance(title, dict) or title.get("title_id") != expected_id:
            raise ValueError("recheck title list is incomplete or out of order")
        path = _local_path(title.get("path"), f"title {expected_id} path")
        if path.parent != old_job / "titles" or path.name != f"title-{expected_id:03}.mkv":
            raise ValueError(f"title {expected_id} path is outside the saved neutral-title directory")
        if _is_reparse(path) or not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(f"title {expected_id} is absent, empty, or a reparse point")
        if not re.fullmatch(r"[0-9a-f]{64}", str(title.get("sha256", ""))):
            raise ValueError(f"title {expected_id} saved hash is missing or malformed")
        if _sha256(path) != title["sha256"] or path.stat().st_size != title.get("bytes"):
            raise ValueError(f"title {expected_id} differs from its saved native-output hash or size")
        normalized.append((title, path))
    receipt.mkdir(parents=True, exist_ok=False)
    report = {**program_stamp(), "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "derivatives_incomplete", "title_count": plan["title_count"],
        "verified_title_count": 0, "recheck_only": True,
        "native_baseline": {"old_job": str(old_job), "old_result_sha256": plan["old_result_sha256"],
            "old_native_log_sha256": plan["old_native_log_sha256"],
            "limits": "Native output counts and hashes do not prove original-DVD semantic completeness"},
        "source": plan["source"], "tool_sha256": plan["tool_sha256"],
        "stream_selection_contract": "Saved MakeMKV title set; default stream selection and DVD angle coverage are not guaranteed",
        "subtitle_rendering": "unverified",
        "duration_diagnostic": "TINFO duration drift is retained as diagnostic; its cause is unknown",
        "blockers": [], "omissions": [], "titles": [], "logs": {}}
    verify_plan = {"ready": True, "tools": tools, "inspection": plan.get("inspection")}
    for original, path in normalized:
        item = {key: original.get(key) for key in ("title_id", "bytes", "sha256", "path",
            "makemkv_filename")}
        item["source_streams"] = _source_streams(verify_plan["inspection"], item["title_id"])
        item["logs"] = {}
        before = _sha256(path)
        try:
            _verify_title(verify_plan, item, path, receipt, report)
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
                subprocess.TimeoutExpired) as exc:
            item["status"] = "incomplete"
            item["error"] = str(exc)
            report["blockers"].append(f"title {item['title_id']}: {exc}")
        try:
            after = _sha256(path)
        except OSError:
            after = None
        item["hash_after_sha256"] = after
        if after != before:
            item["status"] = "incomplete"
            item["error"] = "title changed during verification"
            report["blockers"].append(f"title {item['title_id']}: title changed during verification")
        report["titles"].append(item)
    report["verified_title_count"] = sum(item.get("status") == "verified" for item in report["titles"])
    report["status"] = ("derivatives_inspected" if not report["blockers"]
        and report["verified_title_count"] == report["title_count"] else "derivatives_incomplete")
    _write_json(receipt / "report.json", report)
    return report


def _local_log(entry, receipt_dir, *, empty=False):
    if not isinstance(entry, dict):
        raise ValueError("verification log entry is missing")
    path = _local_path(entry.get("path"), "verification log")
    if path.parent != receipt_dir or _is_reparse(path) or not path.is_file():
        raise ValueError("verification log is not a regular file in its receipt folder")
    if path.stat().st_size != entry.get("bytes") or _sha256(path) != entry.get("sha256"):
        raise ValueError("verification log size or hash differs from its receipt")
    if empty and path.stat().st_size:
        raise ValueError("verification error log is not empty")
    return path


def _jpeg_frame(plan, title, title_path, output, title_dir, index, seconds):
    tool = plan["tools"]["ffmpeg"]
    argv = [tool, "-nostdin", "-v", "error", "-xerror", "-ss", f"{seconds:.6f}",
            "-i", str(title_path), "-map", "0:v:0", "-frames:v", "1", "-an", "-sn", "-dn",
            "-vf", "scale=640:480:force_original_aspect_ratio=decrease",
            "-c:v", "mjpeg", "-f", "image2pipe", "-"]
    stem = f"title-{title['title_id']:03}-frame-{index:02}"
    evidence = {"requested_seek_seconds": seconds, "actual_frame_pts": None,
                "argv": argv, "tool_sha256": plan["tool_sha256"]["ffmpeg"]}
    stderr_path = title_dir / f"{stem}.stderr.log"
    exit_code = None
    try:
        result = _run(argv, 90, output)
        exit_code = result.returncode
        stdout, stderr = result.stdout or b"", result.stderr or b""
        stderr_path.write_bytes(stderr)
        evidence.update({"exit_code": exit_code, "result": "success" if exit_code == 0 and not stderr else "incomplete",
            "stderr": {"path": str(stderr_path),
            "bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest()},
            "stdout_bytes": len(stdout), "stdout_sha256": hashlib.sha256(stdout).hexdigest()})
        if len(stdout) <= FRAME_MAX_BYTES and stdout:
            partial = title_dir / f"{stem}.jpg.partial"
            partial.write_bytes(stdout)
            evidence["partial_path"] = str(partial)
        if exit_code != 0 or stderr:
            raise ValueError("FFmpeg frame command failed or wrote to stderr")
        if len(stdout) > FRAME_MAX_BYTES or len(stdout) < 4 or not stdout.startswith(b"\xff\xd8") or not stdout.endswith(b"\xff\xd9"):
            raise ValueError("FFmpeg output is oversized or is not a complete JPEG")
        frame = title_dir / f"{stem}.jpg"
        frame.write_bytes(stdout)
        evidence.update({"status": "saved", "path": str(frame), "bytes": len(stdout),
                         "sha256": hashlib.sha256(stdout).hexdigest()})
        partial.unlink()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        evidence.update({"status": "incomplete", "result": "incomplete", "exit_code": exit_code, "error": str(exc)})
        if not stderr_path.exists():
            stderr_path.write_bytes(b"")
            evidence["stderr"] = {"path": str(stderr_path), "bytes": 0,
                                  "sha256": hashlib.sha256(b"").hexdigest()}
        if isinstance(exc, subprocess.TimeoutExpired):
            stderr = exc.stderr or b""
            if isinstance(stderr, str):
                stderr = stderr.encode()
            stderr_path.write_bytes(stderr)
            evidence["stderr"] = {"path": str(stderr_path), "bytes": len(stderr),
                                  "sha256": hashlib.sha256(stderr).hexdigest()}
            stdout = exc.stdout or b""
            if isinstance(stdout, str):
                stdout = stdout.encode()
            evidence.update({"stdout_bytes": len(stdout),
                             "stdout_sha256": hashlib.sha256(stdout).hexdigest()})
            if stdout and len(stdout) <= FRAME_MAX_BYTES:
                partial = title_dir / f"{stem}.jpg.partial"
                if not partial.exists():
                    partial.write_bytes(stdout)
                evidence["partial_path"] = str(partial)
        return evidence
    return evidence


def _raw_disc_candidate(inspection):
    records = inspection.get("robot", {}).get("records", [])
    for record in records:
        fields = record.get("fields", []) if isinstance(record, dict) else []
        if isinstance(record, dict) and record.get("prefix") == "CINFO" and len(fields) == 3 and fields[:2] == ["2", "0"] and fields[2]:
            return fields[2]
    return None


def dvd_library_plan(plan, verification, verification_path, verification_sha256, output, preview=False):
    """Build local, unmapped title rows from a successful saved local recheck."""
    verification_path = _local_path(str(verification_path), "verification receipt")
    verification_dir = verification_path.parent
    if not isinstance(verification, dict) or verification.get("status") != "derivatives_inspected":
        raise ValueError("library planning requires a successful local derivative recheck")
    if ("source_consistency_error" not in verification or verification["source_consistency_error"] is not None
            or verification.get("blockers") != []):
        raise ValueError("local derivative recheck has a source-consistency error or blockers")
    if verification.get("recheck_only") is not True or verification.get("verified_title_count") != plan.get("title_count"):
        raise ValueError("verification receipt is not a complete local recheck for this job")
    baseline = verification.get("native_baseline", {})
    if (baseline.get("old_job") != plan.get("old_job")
            or baseline.get("old_result_sha256") != plan.get("old_result_sha256")
            or baseline.get("old_native_log_sha256") != plan.get("old_native_log_sha256")):
        raise ValueError("local recheck native baseline differs from the existing job")
    if not re.fullmatch(r"[0-9a-f]{64}", str(verification_sha256)):
        raise ValueError("verification receipt hash is malformed")
    if preview and _tool(plan.get("tools", {}).get("ffmpeg"), "ffmpeg")[1] != plan.get("tool_sha256", {}).get("ffmpeg"):
        raise ValueError("configured ffmpeg hash changed")
    rows = verification.get("titles")
    expected = plan.get("titles")
    if not isinstance(rows, list) or len(rows) != plan.get("title_count") or not isinstance(expected, list) or len(expected) != len(rows):
        raise ValueError("local derivative recheck does not contain every title")
    checked = []
    seen = set()
    for title_id, (row, original) in enumerate(zip(rows, expected)):
        if not isinstance(row, dict) or not isinstance(original, dict) or row.get("title_id") != title_id or title_id in seen:
            raise ValueError("local derivative recheck title IDs are missing, duplicated, or out of order")
        seen.add(title_id)
        for field in ("path", "bytes", "sha256", "makemkv_filename"):
            if row.get(field) != original.get(field):
                raise ValueError(f"title {title_id} {field} differs from the original local job")
        if (row.get("status") != "verified" or row.get("hash_after_sha256") != original.get("sha256")
                or row.get("ffprobe_returncode") != 0 or row.get("packet_scan_returncode") != 0
                or row.get("decode_returncode") != 0 or row.get("decoded_audio_video") is not True):
            raise ValueError(f"title {title_id} lacks complete successful verification")
        logs = row.get("logs", {})
        prefix = f"title-{title_id:03}"
        for name in (f"ffprobe-{prefix}.stdout.log", f"ffprobe-{prefix}.stderr.log",
                     f"ffprobe-{prefix}.packets.log", f"ffprobe-{prefix}.packets.stderr.log",
                     f"ffmpeg-{prefix}.stderr.log"):
            path = _local_log(logs.get(name), verification_dir,
                              empty=name.endswith("stderr.log"))
            if name.endswith("stderr.log") and path.stat().st_size:
                raise ValueError(f"title {title_id} verification error log is not empty")
        if not isinstance(row.get("ffprobe"), dict) or not isinstance(row["ffprobe"].get("streams"), list):
            raise ValueError(f"title {title_id} lacks verified stream metadata")
        title_path = _local_path(original.get("path"), f"title {title_id} path")
        if title_path.parent != Path(plan["old_job"]) / "titles" or title_path.stat().st_size != original.get("bytes"):
            raise ValueError(f"title {title_id} is outside its original local title folder or changed size")
        digest = _sha256(title_path)
        if digest != original.get("sha256") or digest != row.get("hash_after_sha256"):
            raise ValueError(f"title {title_id} no longer matches its original verified hash")
        checked.append((row, original, title_path))
    if len(seen) != plan.get("title_count"):
        raise ValueError("local derivative recheck title IDs are not unique")

    destination = Path(output).expanduser().absolute()
    if destination.exists() or destination.is_symlink() or str(destination).startswith("\\\\"):
        raise ValueError("library inspection output must be new and local")
    destination.mkdir(parents=True, exist_ok=False)
    report = {**program_stamp(), "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "pending_mapping", "old_job": plan["old_job"], "verification_path": str(verification_path),
        "verification_sha256": verification_sha256, "native_baseline": baseline,
        "preview": bool(preview), "preview_limit": "lossy visual evidence only; not a media deliverable",
        "title_count": len(checked), "pending_mapping_count": len(checked), "blockers": [], "titles": [],
        "result_path": str(destination / "result.json"), "source_consistency_error": None}
    raw_candidate = _raw_disc_candidate(plan.get("inspection", {}))
    for row, original, title_path in checked:
        title_id = row["title_id"]
        title_dir = destination / f"title-{title_id:03}"
        item = {"title_id": title_id, "mapping_status": "pending", "destination": None,
            "expected_sha256": original["sha256"], "expected_bytes": original["bytes"],
            "source_path": str(title_path), "source_filename": original["makemkv_filename"],
            "raw_disc_candidate": raw_candidate,
            "provenance": {"old_job": plan["old_job"], "old_result_sha256": plan["old_result_sha256"],
                "native_log_sha256": plan["old_native_log_sha256"], "verification_sha256": verification_sha256},
            "actual_verified_stream_metadata": {key: row.get(key) for key in
                ("ffprobe", "packet_coverage", "subtitle_coverage", "duration_diagnostic")},
            "omissions": [omission for omission in verification.get("omissions", [])
                          if omission.get("title_id") == title_id], "frame_evidence": []}
        if preview:
            duration = row["ffprobe"].get("duration_seconds")
            if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration <= 0:
                item["frame_evidence_error"] = "verified ffprobe duration is missing or not positive and finite"
            else:
                seconds = sorted({min(5.0, duration / 4), duration / 4, 3 * duration / 4})
                title_dir.mkdir(exist_ok=False)
                item["frame_evidence"] = [_jpeg_frame(plan, row, title_path, destination,
                    title_dir, index, seek) for index, seek in enumerate(seconds)]
                if any(frame.get("status") != "saved" for frame in item["frame_evidence"]):
                    report["blockers"].append(f"title {title_id}: one or more preview frames are incomplete")
            if item.get("frame_evidence_error"):
                report["blockers"].append(f"title {title_id}: {item['frame_evidence_error']}")
        report["titles"].append(item)
    for _row, original, title_path in checked:
        try:
            if title_path.stat().st_size != original["bytes"] or _sha256(title_path) != original["sha256"]:
                report["blockers"].append(f"title {original['title_id']}: source changed during library planning")
        except OSError as exc:
            report["blockers"].append(f"title {original['title_id']}: source could not be checked after planning: {exc}")
    if preview and _tool(plan.get("tools", {}).get("ffmpeg"), "ffmpeg")[1] != plan.get("tool_sha256", {}).get("ffmpeg"):
        report["blockers"].append("configured ffmpeg hash changed during preview capture")
    report["status"] = "pending_mapping" if not report["blockers"] else "incomplete"
    _write_json(destination / "result.json", report)
    return report
