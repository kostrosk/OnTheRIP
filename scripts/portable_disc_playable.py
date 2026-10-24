"""Publish one verified GameCube or Wii ISO to a fixed EmuDeck folder."""
# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import threading

from portable_disc_identity import parse_header
from portable_disc_version import program_stamp


SSH_FLAGS = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o",
             "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3")
TRANSFER_TIMEOUT = 1800
REMOTE_SCRIPT = r'''
import hashlib, json, os, pathlib, re, sys, uuid
def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)
try:
    header = sys.stdin.buffer.readline(16385)
    if not header.endswith(b"\n") or len(header) > 16384:
        fail("missing or oversized transfer header")
    request = json.loads(header)
    platform = request["platform"]
    root = request["directory"]
    name = request["name"]
    size = request["bytes"]
    expected = request["sha256"]
    if platform not in {"gamecube", "wii"}: fail("unsupported playable platform")
    if not isinstance(root, str) or not root.startswith("/") or "\\" in root or ".." in pathlib.PurePosixPath(root).parts or any(ord(char) < 32 or ord(char) == 127 for char in root): fail("destination root must be an absolute safe POSIX path")
    if not isinstance(name, str) or name != pathlib.PurePosixPath(name).name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,179}\.iso", name, re.I): fail("unsafe ISO filename")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1: fail("invalid payload size")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected): fail("invalid SHA-256")
    directory = pathlib.Path(root)
    if not directory.is_absolute(): fail("destination folder must be absolute")
    try:
        resolved_directory = directory.resolve(strict=True)
    except (OSError, RuntimeError):
        fail("destination folder must already exist and resolve")
    if not resolved_directory.is_dir(): fail("destination folder must already exist")
    final = resolved_directory / name
    configured_destination = root + "/" + name
    if final.is_symlink(): fail("destination is a symlink")
    if final.exists():
        if not final.is_file(): fail("destination exists and is not a regular file")
        digest = hashlib.sha256()
        count = 0
        with final.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block: break
                digest.update(block); count += len(block)
        if count != size or digest.hexdigest() != expected: fail("destination exists with different contents")
        print(json.dumps({"destination": configured_destination, "resolved_destination": str(final), "bytes": count, "sha256": digest.hexdigest(), "verification": "verified", "retained_partial": None}))
        raise SystemExit(0)
    partial = directory / ("." + name + "." + uuid.uuid4().hex + ".partial")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(partial, flags, 0o600)
    digest = hashlib.sha256()
    count = 0
    with os.fdopen(fd, "wb") as output:
        while count < size:
            block = sys.stdin.buffer.read(min(1024 * 1024, size - count))
            if not block: fail("payload ended before declared byte count")
            output.write(block); digest.update(block); count += len(block)
        output.flush(); os.fsync(output.fileno())
    if sys.stdin.buffer.read(1): fail("payload exceeds declared byte count")
    if digest.hexdigest() != expected: fail("received payload hash does not match request")
    check = hashlib.sha256(); check_count = 0
    with partial.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block: break
            check.update(block); check_count += len(block)
    if check_count != size or check.hexdigest() != expected: fail("partial reread hash does not match request")
    try:
        os.link(partial, final, follow_symlinks=False)
    except FileExistsError:
        if final.is_symlink() or not final.is_file(): fail("destination appeared and is not a regular file")
        digest = hashlib.sha256(); count = 0
        with final.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block: break
                digest.update(block); count += len(block)
        if count != size or digest.hexdigest() != expected: fail("destination appeared with different contents")
    digest = hashlib.sha256(); count = 0
    with final.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block: break
            digest.update(block); count += len(block)
    if count != size or digest.hexdigest() != expected: fail("published destination reread failed")
    print(json.dumps({"destination": configured_destination, "resolved_destination": str(final), "bytes": count, "sha256": digest.hexdigest(), "verification": "verified", "retained_partial": str(partial)}))
except SystemExit:
    raise
except Exception as exc:
    fail("transfer helper failed: " + str(exc))
'''


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_link(path):
    info = Path(path).lstat()
    if Path(path).is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError(f"archive contains a link or reparse point: {path}")


def _reject_link_chain(path):
    current = Path(path).absolute()
    for item in (current, *current.parents):
        _reject_link(item)


def _safe_record_path(value):
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("manifest record path must be a relative POSIX path")
    rel = PurePosixPath(value)
    if rel.is_absolute() or not rel.parts or any(part in {"", ".", ".."} for part in rel.parts):
        raise ValueError("manifest record path is unsafe")
    return rel


def archive_info(backup_dir):
    folder = Path(backup_dir).absolute()
    _reject_link_chain(folder)
    if not folder.is_dir():
        raise ValueError("backup folder is not a directory")
    marker = folder / "backup_complete.json"
    _reject_link(marker)
    manifest = json.loads(marker.read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("version"), int)
            or isinstance(manifest.get("version"), bool) or manifest.get("version") != 1):
        raise ValueError("backup manifest schema must be version 1")
    metadata = manifest.get("metadata")
    records = manifest.get("records")
    if not isinstance(metadata, dict) or not isinstance(records, list) or not records:
        raise ValueError("backup manifest metadata or records are missing")
    classification = metadata.get("classification")
    if classification not in {"gamecube", "wii"}:
        raise ValueError(f"unsupported playable format: {classification!r}; PS3 folders, Xbox conversions, and video are not ISO copies")
    fingerprint = metadata.get("fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(rf"{classification}:[A-Za-z0-9]{{6}}:disc[1-9][0-9]*:rev(?:0|[1-9][0-9]*)", fingerprint):
        raise ValueError("backup metadata has an invalid logical-disc fingerprint")
    data = folder / "data"
    _reject_link(data)
    if not data.is_dir():
        raise ValueError("backup data folder is missing")
    expected = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("backup record is not an object")
        rel = _safe_record_path(record.get("path"))
        if rel.as_posix() in expected:
            raise ValueError("backup manifest contains duplicate paths")
        if not isinstance(record.get("bytes"), int) or isinstance(record.get("bytes"), bool) or record["bytes"] < 0:
            raise ValueError("backup record has invalid byte count")
        if not isinstance(record.get("sha256"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", record["sha256"]):
            raise ValueError("backup record has invalid SHA-256")
        expected[rel.as_posix()] = record
    actual = {}
    for path in data.rglob("*"):
        _reject_link(path)
        if path.is_file():
            actual[path.relative_to(data).as_posix()] = path
    if set(actual) != set(expected):
        raise ValueError("backup file list does not match its manifest")
    verified_records = []
    for name, record in expected.items():
        path = actual[name]
        if path.stat().st_size != record["bytes"] or _sha256(path) != record["sha256"].lower():
            raise ValueError(f"backup file does not match its recorded size and hash: {name}")
        verified_records.append(record)
    iso_records = [r for r in verified_records if PurePosixPath(r["path"]).suffix.lower() == ".iso"]
    if len(iso_records) != 1 or len(verified_records) != 1:
        raise ValueError("playable copy requires exactly one .iso file and no other backup records")
    record = iso_records[0]
    source = actual[record["path"]]
    with source.open("rb") as stream:
        header = parse_header(stream.read(0x100))["metadata"]
    if header.get("classification") != classification or header.get("fingerprint") != fingerprint:
        raise ValueError("backup metadata conflicts with the ISO logical header")
    title = metadata.get("title")
    if title and header.get("title") and title != header["title"]:
        raise ValueError("backup title conflicts with the ISO logical header")
    return {"metadata": metadata, "fingerprint": fingerprint, "classification": classification,
            "records": verified_records, "archive": str(folder), "source": str(source),
            "bytes": record["bytes"], "sha256": record["sha256"].lower()}


def placement_target(cfg, metadata):
    classification = metadata.get("classification") if isinstance(metadata, dict) else None
    if classification not in {"gamecube", "wii"}:
        raise ValueError(f"unsupported playable format: {classification!r}")
    platforms = cfg.get("platforms") if isinstance(cfg, dict) else None
    playable = platforms.get(classification, {}).get("playable") if isinstance(platforms, dict) else None
    if not isinstance(playable, dict):
        raise ValueError(f"no playable target is configured for {classification}")
    host = playable.get("host")
    directory = playable.get("directory")
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}@[A-Za-z0-9.-]{1,253}", host):
        raise ValueError("playable target host must be a fixed username@host value")
    if not isinstance(directory, str) or not directory.startswith("/") or "\\" in directory:
        raise ValueError("playable target directory must be an absolute POSIX path")
    if ".." in PurePosixPath(directory).parts:
        raise ValueError("playable target directory cannot contain parent traversal")
    if any(ord(char) < 32 or ord(char) == 127 for char in directory):
        raise ValueError("playable target directory cannot contain control characters")
    return {"host": host, "directory": directory}


def playable_filename(info):
    """Return the verified NAS ISO basename without losing its disc identity."""
    name = Path(info["source"]).name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,179}\.iso", name, re.I):
        raise ValueError("verified NAS ISO basename is not a safe portable filename")
    return name


def _ssh_path():
    windir = os.environ.get("WINDIR")
    candidate = Path(windir) / "System32" / "OpenSSH" / "ssh.exe" if os.name == "nt" and windir else None
    return str(candidate) if candidate and candidate.is_file() else "ssh"


def _hash_source(path):
    before = Path(path).stat()
    digest = _sha256(path)
    after = Path(path).stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("NAS source changed during hash read")
    return before, digest


def _run_transfer(target, info, filename):
    source = Path(info["source"])
    before, actual_hash = _hash_source(source)
    if actual_hash != info["sha256"] or before.st_size != info["bytes"]:
        raise ValueError("NAS source changed after archive verification")
    request = {"platform": info["classification"], "directory": target["directory"],
               "name": filename, "bytes": info["bytes"], "sha256": actual_hash}
    remote = shlex.join(["python3", "-c", REMOTE_SCRIPT])
    command = [_ssh_path(), *SSH_FLAGS, target["host"], remote]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False, bufsize=0)
    stdout_parts, stderr_parts = [], []
    def drain(pipe, parts):
        while True:
            block = pipe.read(4096)
            if not block:
                return
            if sum(map(len, parts)) < 65536:
                parts.append(block[:max(0, 65536 - sum(map(len, parts)))])
    readers = [threading.Thread(target=drain, args=(process.stdout, stdout_parts), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, stderr_parts), daemon=True)]
    for thread in readers:
        thread.start()
    write_error = []
    def write_payload():
        try:
            def write_all(block):
                view = memoryview(block)
                while view:
                    written = process.stdin.write(view)
                    if not written:
                        raise BrokenPipeError("SSH stdin accepted no payload bytes")
                    view = view[written:]
            write_all((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
            with source.open("rb") as stream:
                while True:
                    block = stream.read(1024 * 1024)
                    if not block:
                        break
                    write_all(block)
        except (BrokenPipeError, OSError) as exc:
            write_error.append(exc)
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass
    writer = threading.Thread(target=write_payload, daemon=True)
    writer.start()
    try:
        returncode = process.wait(timeout=TRANSFER_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        writer.join(timeout=5)
        raise TimeoutError("SSH playable-copy transfer exceeded its time limit")
    writer.join(timeout=5)
    for thread in readers:
        thread.join(timeout=5)
    if writer.is_alive():
        raise TimeoutError("SSH payload writer did not stop after the remote process exited")
    stdout = b"".join(stdout_parts).decode("utf-8", errors="replace").strip()
    stderr = b"".join(stderr_parts).decode("utf-8", errors="replace").strip()
    if returncode != 0:
        raise RuntimeError(f"SSH playable-copy failed ({returncode}): {stderr or write_error}")
    rows = [line for line in stdout.splitlines() if line.strip()]
    if len(rows) != 1:
        raise RuntimeError("SSH helper did not return exactly one JSON result")
    result = json.loads(rows[0])
    if result.get("verification") != "verified" or result.get("sha256") != actual_hash or result.get("bytes") != before.st_size:
        raise RuntimeError("remote result does not match the NAS source hash and size")
    expected_destination = target["directory"] + "/" + filename
    if result.get("destination") != expected_destination:
        raise RuntimeError("remote result destination does not match the fixed configured target")
    if not isinstance(result.get("resolved_destination"), str) or not result["resolved_destination"].startswith("/"):
        raise RuntimeError("remote result lacks an absolute resolved destination")
    after, end_hash = _hash_source(source)
    if end_hash != actual_hash or (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        raise RuntimeError("NAS source changed during SSH transfer")
    return result, actual_hash


def place_backup(cfg, backup_dir):
    info = archive_info(backup_dir)
    target = placement_target(cfg, info["metadata"])
    filename = playable_filename(info)
    remote, source_hash = _run_transfer(target, info, filename)
    return {"archive": info["archive"], "source": info["source"], "fingerprint": info["fingerprint"],
            "classification": info["classification"], "title": info["metadata"].get("title"),
            "platform": info["metadata"].get("platform"), "host": target["host"],
            "destination": remote["destination"], "bytes": remote["bytes"],
            "resolved_destination": remote["resolved_destination"],
            "source_sha256": source_hash, "sha256": remote["sha256"],
            "verification": "verified", "retained_partial": remote.get("retained_partial"),
            **program_stamp()}
