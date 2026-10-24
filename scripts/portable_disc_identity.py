"""Bounded, read-only optical-disc identity probes using Python's standard library."""
# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import re
import struct
import sys
from ctypes import wintypes
from portable_disc_omnidrive import read_header as read_scsi_header

MAX_READ = 64 * 1024
IOCTL_CDROM_READ_TOC_EX = 0x00024054
IOCTL_CDROM_GET_CONFIGURATION = 0x00024058
IOCTL_STORAGE_CHECK_VERIFY2 = 0x002D0800
_PROFILES = {
    0x0008: "CD-ROM", 0x0010: "DVD-ROM", 0x0011: "DVD-R sequential",
    0x0012: "DVD-RAM", 0x0013: "DVD-RW restricted overwrite",
    0x0014: "DVD-RW sequential", 0x001A: "DVD+RW", 0x001B: "DVD+R",
    0x0020: "DDCD-ROM", 0x0040: "BD-ROM", 0x0041: "BD-R sequential",
    0x0042: "BD-R random recording", 0x0043: "BD-RE",
}


def _error(operation, exc):
    item = {"operation": operation, "error": str(exc)}
    code = getattr(exc, "winerror", None)
    if code is not None:
        item["winerror"] = code
    code = getattr(exc, "errno", None)
    if code is not None:
        item["errno"] = code
    return item


def _clean_text(raw):
    try: text = raw.split(b"\0", 1)[0].decode("ascii").strip()
    except UnicodeDecodeError: return None
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in text): return None
    return text if text and any(ch.isalnum() for ch in text) else None


def parse_header(data):
    """Parse recognized GameCube/Wii headers and filesystem signatures in bytes."""
    metadata, evidence = {}, []
    if len(data) >= 0x28:
        game_id = _clean_text(data[:6])
        if game_id and re.fullmatch(r"[A-Za-z0-9]{6}", game_id):
            magic_gc = len(data) >= 0x20 and struct.unpack_from(">I", data, 0x1C)[0] == 0xC2339F3D
            magic_wii = struct.unpack_from(">I", data, 0x18)[0] == 0x5D1C9EA3
            if magic_gc and magic_wii:
                return {"metadata": {}, "evidence": [], "errors": [{"operation": "parse_header", "error": "conflicting platform header markers"}]}
            if magic_gc or magic_wii:
                platform = "wii" if magic_wii else "gamecube"
                title = _clean_text(data[0x20:0x80]) if len(data) >= 0x80 else None
                metadata = {
                    "classification": platform,
                    "title_id": game_id,
                    "platform": "Wii" if platform == "wii" else "GameCube",
                    "identity_scope": "embedded logical software header; not a unique physical disc",
                }
                metadata["disc_number"] = data[6] + 1
                metadata["revision"] = data[7]
                if title:
                    metadata["title"] = title
                metadata["fingerprint"] = f"{platform}:{game_id}:disc{data[6] + 1}:rev{data[7]}"
                evidence.append({"kind": "header", "status": "recognized_candidate", "format": platform,
                                 "game_id": game_id, "title_embedded": title is not None})
    # ISO9660 primary volume descriptor at logical sector 16 (2048-byte sectors).
    pvd = 16 * 2048
    if len(data) >= pvd + 7 and data[pvd] == 1 and data[pvd + 1:pvd + 6] == b"CD001" and data[pvd + 6] == 1:
        evidence.append({"kind": "filesystem", "status": "recognized_signature", "format": "ISO9660",
                         "meaning": "filesystem signature only; content type and title unknown"})
        if not metadata:
            metadata = {"classification": "iso9660", "identity_scope": "filesystem signature only; title and physical disc unknown"}
    # UDF volume recognition sequence markers; these do not imply DVD-Video.
    markers = []
    for sector in range(16, min(len(data) // 2048, 32)):
        marker = data[sector * 2048 + 1:sector * 2048 + 6]
        if marker in (b"BEA01", b"NSR02", b"NSR03", b"TEA01"):
            markers.append(marker.decode("ascii"))
    if "NSR02" in markers or "NSR03" in markers:
        evidence.append({"kind": "filesystem", "status": "recognized_signature", "format": "UDF",
                         "markers": markers, "meaning": "filesystem signature only; content type and title unknown"})
        if not metadata:
            metadata = {"classification": "udf", "identity_scope": "filesystem signature only; title and physical disc unknown"}
    return {"evidence": evidence, "errors": [], "metadata": metadata}


def _musicbrainz_disc_id(first, last, offsets):
    if first != 1 or not (1 <= first <= last <= 99) or len(offsets) != last - first + 2:
        return None
    # Input offsets are track starts followed by the lead-out.
    leadout, starts = offsets[-1], offsets[:-1]
    values = [leadout, *starts, *([0] * (99 - len(starts)))]
    payload = f"{first:02X}{last:02X}" + "".join(f"{n:08X}" for n in values)
    digest = base64.b64encode(hashlib.sha1(payload.encode("ascii")).digest())
    return digest.decode("ascii").translate(str.maketrans("+/=", "._-"))


def _parse_toc(raw):
    if len(raw) < 4:
        raise ValueError("TOC response is shorter than its header")
    length = int.from_bytes(raw[:2], "big")
    end = 2 + length
    if length < 10 or end > len(raw) or (length - 2) % 8:
        raise ValueError("TOC response length or track records are incomplete")
    first, last = raw[2], raw[3]
    records = [raw[pos:pos + 8] for pos in range(4, end, 8)]
    expected = list(range(first, last + 1)) + [0xAA]
    if not (1 <= first <= last <= 99) or len(records) != len(expected):
        raise ValueError("TOC does not contain a complete numbered track list and lead-out")
    tracks, offsets = [], []
    for record, number in zip(records, expected):
        if record[2] != number:
            raise ValueError("TOC track numbers are not complete and ordered")
        control = record[1] & 0x0F
        lba = int.from_bytes(record[4:8], "big")
        tracks.append({"track": number, "control": control, "is_data": bool(control & 0x04), "lba": lba})
        offsets.append(lba + 150)
    if any(a >= b for a, b in zip(offsets, offsets[1:])):
        raise ValueError("TOC offsets and lead-out must strictly increase")
    audio = all(not row["is_data"] for row in tracks[:-1])
    result = {"kind": "toc", "status": "complete", "first_track": first, "last_track": last,
              "tracks": tracks[:-1], "leadout_lba": tracks[-1]["lba"], "all_tracks_audio": audio}
    if audio:
        disc_id = _musicbrainz_disc_id(first, last, offsets)
        if disc_id:
            result["musicbrainz_disc_id"] = disc_id
    return result


def _profile_name(code):
    return _PROFILES.get(code, f"unknown MMC profile 0x{code:04X}")


def _windows_probe(drive, mounted_reader=None):
    if not re.fullmatch(r"[A-Za-z]:?\\?", str(drive)):
        raise ValueError("Windows drive must be a letter such as E: or E:\\")
    letter = str(drive)[0].upper()
    device = rf"\\.\{letter}:"
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
                                       wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    kernel.DeviceIoControl.restype = wintypes.BOOL
    kernel.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    kernel.ReadFile.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(device, 0x80000000, 0x1 | 0x2, None, 3, 0, None)  # READ, shared, OPEN_EXISTING
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    evidence, errors, metadata = [], [], {}
    def change_count():
        value, returned = wintypes.DWORD(), wintypes.DWORD()
        if kernel.DeviceIoControl(handle, IOCTL_STORAGE_CHECK_VERIFY2, None, 0,
                                  ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(returned), None):
            if returned.value == ctypes.sizeof(value): return value.value
            errors.append({"operation": "media_change_counter", "error": "no counter returned"})
        else:
            errors.append(_error("media_change_counter", ctypes.WinError(ctypes.get_last_error())))
        return None

    before = after = None
    profile_code = None
    try:
        before = change_count()
        mounted_identified = bool(mounted_reader()) if mounted_reader else False
        # GET CONFIGURATION: current profile only. Feature=0; request type CURRENT=1.
        class _ConfigInput(ctypes.Structure):
            _fields_ = [("feature", wintypes.ULONG), ("request_type", wintypes.ULONG),
                        ("reserved", ctypes.c_void_p * 2)]
        query = _ConfigInput(0, 1, (ctypes.c_void_p * 2)())
        out = ctypes.create_string_buffer(64)
        returned = wintypes.DWORD()
        if kernel.DeviceIoControl(handle, IOCTL_CDROM_GET_CONFIGURATION, ctypes.byref(query),
                                  ctypes.sizeof(query), out, len(out), ctypes.byref(returned), None):
            if returned.value >= 8:
                code = int.from_bytes(out.raw[6:8], "big")
                profile_code = code
                evidence.append({"kind": "profile", "status": "reported", "profile_code": code,
                                 "profile": _profile_name(code), "meaning": "drive/media profile; does not identify title"})
            else:
                errors.append({"operation": "get_configuration_parse", "error": "response shorter than profile header"})
        else:
            errors.append(_error("get_configuration", ctypes.WinError(ctypes.get_last_error())))

        # READ_TOC_EX format=TOC, LBA addressing, session/track zero.
        toc_input = ctypes.create_string_buffer(bytes((0, 0, 0, 0)))
        toc_out = ctypes.create_string_buffer(804)
        returned = wintypes.DWORD()
        if kernel.DeviceIoControl(handle, IOCTL_CDROM_READ_TOC_EX, toc_input, 4,
                                  toc_out, len(toc_out), ctypes.byref(returned), None):
            try:
                toc = _parse_toc(toc_out.raw[:returned.value])
                evidence.append(toc)
                if toc.get("all_tracks_audio") and toc.get("musicbrainz_disc_id"):
                    metadata.update({"classification": "audio_cd", "fingerprint": "musicbrainz:" + toc["musicbrainz_disc_id"],
                                     "identity_scope": "complete all-audio TOC fingerprint; title and unique physical disc unknown"})
            except ValueError as exc:
                errors.append({"operation": "read_toc_parse", "error": str(exc)})
        else:
            errors.append(_error("read_toc_ex", ctypes.WinError(ctypes.get_last_error())))

        # A single sequential read from byte zero, capped at 64 KiB.
        buf = ctypes.create_string_buffer(MAX_READ)
        returned = wintypes.DWORD()
        if mounted_identified:
            evidence.append({"kind": "header_read", "status": "not_needed", "reason": "mounted metadata supplied a logical identity"})
        elif kernel.ReadFile(handle, buf, MAX_READ, ctypes.byref(returned), None):
            data = buf.raw[:returned.value]
            parsed = parse_header(data)
            evidence.extend(parsed["evidence"])
            if parsed["metadata"]:
                metadata = parsed["metadata"]
            evidence.append({"kind": "header_read", "status": "read", "bytes_read": len(data), "limit": MAX_READ})
        else:
            errors.append(_error("read_header", ctypes.WinError(ctypes.get_last_error())))
        if not mounted_identified and not metadata.get("fingerprint") and profile_code == 0x10:
            fallback = read_scsi_header(drive)
            evidence.extend(fallback["evidence"])
            errors.extend(fallback["errors"])
            identities = []
            for candidate in fallback["candidates"]:
                parsed = parse_header(candidate["data"])
                for item in parsed["evidence"]: item["source"] = candidate["method"]
                evidence.extend(parsed["evidence"])
                errors.extend(parsed["errors"])
                if parsed["metadata"].get("fingerprint"):
                    identities.append(parsed["metadata"])
            if identities and all(item["fingerprint"] == identities[0]["fingerprint"] for item in identities):
                metadata = identities[0]
            elif identities:
                metadata = {}
                errors.append({"operation": "identity_consistency", "error": "conflicting bounded header identities"})
        after = change_count()
        if before is not None and after is not None and before != after:
            metadata = {}
            for item in evidence: item["invalidated_by_media_change"] = True
            errors.append({"operation": "identity_consistency", "error": "media changed during the probe; identity discarded"})
        evidence.append({"kind": "media_change_observation", "before": before, "after": after,
                         "status": "changed" if before is not None and after is not None and before != after else ("stable_counter" if before is not None and after is not None else "unavailable"),
                         "meaning": "OS change observation, not a unique physical-disc fingerprint"})
    finally:
        kernel.CloseHandle(handle)
    consistency = "changed" if before is not None and after is not None and before != after else ("stable_counter" if before is not None and after is not None else "unavailable")
    return {"evidence": evidence, "errors": errors, "metadata": metadata, "disc_change_count": after, "identity_consistency": consistency}


def _linux_probe(drive, mounted_reader=None):
    if not re.fullmatch(r"/dev/sr[0-9]+", str(drive)):
        raise ValueError("Linux drive must be an optical device such as /dev/sr0")
    evidence, errors, metadata = [], [], {}
    fd = None
    try:
        if mounted_reader and mounted_reader():
            return {"evidence": [{"kind": "header_read", "status": "not_needed"}], "errors": [], "metadata": {}, "identity_consistency": "unavailable"}
        fd = os.open(drive, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        data = os.read(fd, MAX_READ)
        parsed = parse_header(data)
        evidence.extend(parsed["evidence"])
        metadata.update(parsed["metadata"])
        evidence.append({"kind": "header_read", "status": "read", "bytes_read": len(data), "limit": MAX_READ})
        evidence.append({"kind": "toc", "status": "unsupported", "reason": "Linux TOC ioctl is not implemented"})
        evidence.append({"kind": "profile", "status": "unsupported", "reason": "Linux profile ioctl is not implemented"})
    except OSError as exc:
        errors.append(_error("open_or_read_header", exc))
    except ValueError as exc:
        errors.append({"operation": "validate_drive", "error": str(exc)})
    finally:
        if fd is not None:
            os.close(fd)
    return {"evidence": evidence, "errors": errors, "metadata": metadata}


def probe_raw(drive, mounted_reader=None):
    """Return read-only probe evidence, errors, and supported logical metadata."""
    try:
        if os.name == "nt":
            result = _windows_probe(drive, mounted_reader)
        elif sys.platform.startswith("linux"):
            result = _linux_probe(drive, mounted_reader)
        else:
            result = {"evidence": [], "errors": [{"operation": "probe", "error": "unsupported operating system"}], "metadata": {}}
    except (OSError, ValueError, AttributeError) as exc:
        result = {"evidence": [], "errors": [_error("open_device", exc)], "metadata": {}}
    result.setdefault("disc_change_count", None)
    return result
