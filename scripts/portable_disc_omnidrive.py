"""Fixed, bounded Windows SPTI reads for one optical-disc header sector."""
# SPDX-License-Identifier: GPL-3.0-only
from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes

MAX_READ = 64 * 1024
_IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x0004D014
_INQUIRY = 0x12
_READ12 = 0xA8
_READ_OMNIDRIVE = 0xC0
_INQUIRY_SIZE = 104
_DVD_SECTOR_SIZE = 2048
_OMNI_FRAME_SIZE = 2064
_OMNI_DATA_OFFSET = 12
_INQUIRY_CDB = bytes((_INQUIRY, 0, 0, 0, _INQUIRY_SIZE, 0))
_READ12_CDB = bytes((_READ12, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0))
_OMNI_CDB = bytes((_READ_OMNIDRIVE, 0x01)) + bytes(4) + (1).to_bytes(4, "big") + bytes(2)
_FIXED_READS = {_INQUIRY_CDB: _INQUIRY_SIZE, _READ12_CDB: _DVD_SECTOR_SIZE, _OMNI_CDB: _OMNI_FRAME_SIZE}

# Pinned transport layout: redumper commit 642bdec05c83c52bbfb94f09a81e710118f96370.
# Protocol sources: scsi/mmc.ixx INQUIRY_StandardData, CDB12_Read, CDB12_ReadOmniDrive;
# scsi/cmd.ixx cmd_read_omnidrive; drive.ixx is_omnidrive_firmware;
# dvd/dvd.ixx DataFrame; scsi/sptd.ixx sendCommand.
_SOURCE = "https://github.com/superg/redumper/blob/642bdec05c83c52bbfb94f09a81e710118f96370/"
_XOR_TABLE = None


def first_sector_candidates(frame):
    """Decode only LBA 0 with the published DVD and Nintendo first-block rules."""
    if len(frame) != _OMNI_FRAME_SIZE:
        raise ValueError("a complete 2064-byte DVD frame is required")
    psn = int.from_bytes(frame[1:4], "big")
    if psn != 0x30000:
        raise ValueError(f"frame PSN 0x{psn:06X} does not match fixed LBA-zero PSN 0x030000")
    global _XOR_TABLE
    if _XOR_TABLE is None:
        table, register = bytearray(), 1
        for _ in range(32768):
            table.append(register & 255)
            for _ in range(8):
                register = ((register << 1) & 0x7FFF) | (((register >> 14) ^ (register >> 10)) & 1)
        _XOR_TABLE = bytes(table)
    results = []
    # ECMA-267 scrambler and redumper dvd_scrambler.ixx. Nintendo key is zero
    # only for the first ECC block; no key search or inference from a disc title.
    for method, offset, start in (("dvd", ((psn >> 4) & 15) * 2048, 12),
                                  ("nintendo-first-block-key0", ((psn >> 4) & 15) * 2048 + 15360, 6)):
        decoded = bytearray(frame)
        for i in range(2048):
            index = offset + i
            if index >= 32768: index -= 32767
            decoded[12 + i] ^= _XOR_TABLE[index]
        payload = bytes(decoded[start:start + 2048])
        if _supported_header(payload):
            results.append({"data": payload, "method": "OmniDrive:C0:raw:LBA0:" + method})
    return results


class _PassThrough(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT), ("ScsiStatus", wintypes.BYTE),
        ("PathId", wintypes.BYTE), ("TargetId", wintypes.BYTE),
        ("Lun", wintypes.BYTE), ("CdbLength", wintypes.BYTE),
        ("SenseInfoLength", wintypes.BYTE), ("DataIn", wintypes.BYTE),
        ("DataTransferLength", wintypes.ULONG), ("TimeOutValue", wintypes.ULONG),
        ("DataBuffer", ctypes.c_void_p), ("SenseInfoOffset", wintypes.ULONG),
        ("Cdb", wintypes.BYTE * 16),
    ]


class _Request(ctypes.Structure):
    _fields_ = [("pass_through", _PassThrough), ("sense", wintypes.BYTE * 18)]


def _error(operation, message, **fields):
    return {"operation": operation, "error": str(message), **fields}


def _supported_header(data):
    return (len(data) >= 0x20 and
            (data[0x18:0x1C] == b"\x5d\x1c\x9e\xa3" or
             data[0x1C:0x20] == b"\xc2\x33\x9f\x3d"))


def _omnidrive_version(inquiry):
    # INQUIRY standard data: reserved5 starts at byte 74 in the pinned MMC layout.
    reserved5 = inquiry[74:104]
    if not reserved5.startswith(b"OmniDrive"):
        return None
    if len(reserved5) < 12:
        return None
    version = tuple(reserved5[9:12])
    return version if version >= (1, 0, 4) else None


def _send(kernel, handle, cdb, length):
    if len(cdb) not in (6, 12) or cdb[0] not in (_INQUIRY, _READ12, _READ_OMNIDRIVE):
        raise ValueError("command is outside the fixed read allowlist")
    if length < 0 or length > MAX_READ:
        raise ValueError("transfer length exceeds the 64 KiB limit")
    if _FIXED_READS.get(bytes(cdb)) != length:
        raise ValueError("command or length differs from the fixed LBA-zero reads")
    data = ctypes.create_string_buffer(max(length, 1))
    request = _Request()
    request.pass_through.Length = ctypes.sizeof(_PassThrough)
    request.pass_through.CdbLength = len(cdb)
    request.pass_through.SenseInfoLength = ctypes.sizeof(request.sense)
    request.pass_through.DataIn = 1  # SCSI_IOCTL_DATA_IN
    request.pass_through.DataTransferLength = length
    request.pass_through.TimeOutValue = 10
    request.pass_through.DataBuffer = ctypes.cast(data, ctypes.c_void_p)
    request.pass_through.SenseInfoOffset = _Request.sense.offset
    request.pass_through.Cdb[:len(cdb)] = cdb
    returned = wintypes.DWORD()
    ok = kernel.DeviceIoControl(handle, _IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                ctypes.byref(request), ctypes.sizeof(request),
                                ctypes.byref(request), ctypes.sizeof(request),
                                ctypes.byref(returned), None)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    if returned.value < ctypes.sizeof(_PassThrough):
        raise OSError("driver returned an incomplete pass-through structure")
    status = request.pass_through.ScsiStatus
    transferred = request.pass_through.DataTransferLength
    if status != 0:
        sense = bytes(request.sense)
        raise OSError(f"SCSI status {status}, sense {sense[2] & 0x0f:02x}/"
                      f"{sense[12]:02x}/{sense[13]:02x}")
    if transferred > length:
        raise OSError("device reported more bytes than the fixed buffer")
    return data.raw[:transferred]


def read_header(drive):
    """Return fixed read candidates, evidence, and errors without printing bytes."""
    result = {"candidates": [], "evidence": [], "errors": []}
    if os.name != "nt":
        result["errors"].append(_error("open_device", "Windows SPTI is required"))
        return result
    if not re.fullmatch(r"[A-Za-z]:?\\?", str(drive)):
        result["errors"].append(_error("validate_drive", "drive must be a letter such as E:"))
        return result

    device = rf"\\.\{str(drive)[0].upper()}:"
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
                                       wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    kernel.DeviceIoControl.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(device, 0xC0000000, 0x3, None, 3, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        result["errors"].append(_error("open_device", ctypes.WinError(ctypes.get_last_error())))
        return result

    try:
        inquiry = b""
        inquiry_cdb = _INQUIRY_CDB
        try:
            inquiry = _send(kernel, handle, inquiry_cdb, _INQUIRY_SIZE)
            version = _omnidrive_version(inquiry)
            result["evidence"].append({"kind": "inquiry", "status": "read",
                                       "bytes_read": len(inquiry), "omnidrive_version": version,
                                       "source": _SOURCE + "drive.ixx#L428-L437"})
        except (OSError, ValueError) as exc:
            version = None
            result["errors"].append(_error("inquiry", exc))

        read12_cdb = _READ12_CDB
        standard_ok = False
        try:
            data = _send(kernel, handle, read12_cdb, _DVD_SECTOR_SIZE)
            if len(data) != _DVD_SECTOR_SIZE:
                raise OSError(f"READ(12) returned {len(data)} bytes, expected 2048")
            standard_ok = True
            result["candidates"].append({"data": data, "method": "READ12:LBA0:1x2048"})
            result["evidence"].append({"kind": "read", "method": "READ12", "lba": 0,
                                       "blocks": 1, "block_size": _DVD_SECTOR_SIZE,
                                       "bytes_read": len(data), "supported_header": _supported_header(data),
                                       "source": _SOURCE + "scsi/mmc.ixx#L745"})
        except (OSError, ValueError) as exc:
            result["errors"].append(_error("read12", exc))

        if standard_ok and _supported_header(result["candidates"][0]["data"]):
            return result
        if version is None:
            result["evidence"].append({"kind": "omnidrive_read", "status": "blocked",
                                       "reason": "INQUIRY did not prove OmniDrive firmware v1.0.4 or newer"})
            return result

        cdb = _OMNI_CDB  # DVD data, hardware descrambling off, LBA 0, one sector.
        try:
            frame = _send(kernel, handle, bytes(cdb), _OMNI_FRAME_SIZE)
            if len(frame) != _OMNI_FRAME_SIZE:
                raise OSError(f"READ C0 returned {len(frame)} bytes, expected 2064")
            payload = frame[_OMNI_DATA_OFFSET:_OMNI_DATA_OFFSET + _DVD_SECTOR_SIZE]
            result["candidates"].append({"data": payload, "method": "OmniDrive:C0:DVD:LBA0:1"})
            decoded = first_sector_candidates(frame)
            result["candidates"].extend(decoded)
            result["evidence"].append({"kind": "omnidrive_read", "status": "read",
                                       "lba": 0, "blocks": 1, "frame_bytes": len(frame),
                                       "psn": int.from_bytes(frame[1:4], "big"),
                                       "payload_bytes": len(payload), "hardware_descramble": False,
                                       "decoded_header_candidates": [item["method"] for item in decoded],
                                       "source": _SOURCE + "scsi/cmd.ixx#L471-L489"})
        except (OSError, ValueError) as exc:
            result["errors"].append(_error("omnidrive_read", exc))
        return result
    finally:
        kernel.CloseHandle(handle)
