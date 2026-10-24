# Source and license notices

OnTheRIP is distributed under GPL-3.0-only. See [LICENSE](LICENSE).
The public edition contains Python source and a PowerShell launcher. It contains no third-party executables or media.

## Source provenance

This experimental edition exports the reviewed private development milestone 0.1.0-dev.13.
The public edition removes machine-specific defaults and uses an unconfigured example.
These publication changes date to 2026-10-24. The public version identifies them separately.
Private operational history and configuration are not part of this distribution.

The bounded optical reader follows protocol layouts and first-sector decoding rules from
[redumper](https://github.com/superg/redumper), by its contributors, at commit
`642bdec05c83c52bbfb94f09a81e710118f96370`.
Relevant files include `scsi/cmd.ixx`, `scsi/mmc.ixx`, `scsi/sptd.ixx`,
`dvd/dvd.ixx`, `dvd/dvd_scrambler.ixx`, and `dvd/nintendo.ixx`.
Redumper distributes these sources under [GPLv3](https://github.com/superg/redumper/blob/642bdec05c83c52bbfb94f09a81e710118f96370/LICENSE).
OnTheRIP's Python reader is an adaptation to fixed, bounded header queries, not the redumper executable.
The Nintendo capture verifier follows the same pinned source's frame geometry, stage markers, and state definitions.

GameCube and Wii header constants were checked against
[Dolphin's DiscUtils.h](https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/DiscIO/DiscUtils.h).
Copyright 2021 Dolphin Emulator Project. That source is GPL-2.0-or-later.
The GPLv3 distribution here retains this attribution.

Windows optical structures follow Microsoft's published API documentation.
The audio TOC fingerprint follows [MusicBrainz's Disc ID calculation](https://musicbrainz.org/doc/Disc_ID_Calculation).
These are logical media identifiers, not unique physical-disc identifiers.

## Separate tools

Install capture and inspection tools separately under their own licenses.
OnTheRIP does not redistribute redumper, MakeMKV, FFmpeg, VLC, firmware, BIOS files, or decryption keys.
MakeMKV and other external tools can have separate license or activation requirements.
No external tool's license grants rights to the media that a user processes.
