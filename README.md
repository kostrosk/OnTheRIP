# OnTheRIP

One start replaces repeated manual steps: it selects supported tools, verifies network-storage copies, files configured games, and records completion or pending work. This public export contains the stable dev.13 engine and a generic configuration.

## Install

Use Windows 10 or 11 with Python 3.11 or newer. Install external tools separately. For DVD, GameCube, and Wii capture, install the [official redumper b767 Windows x64 build](https://github.com/superg/redumper/releases/download/b767/redumper-b767-windows-x64.zip). The engine requires the SHA-256 pin in `scripts/portable_disc_wii.py` and rejects a different build. Nintendo-specific raw-header reads require OmniDrive firmware v1.0.4 or newer.

MakeMKV and VLC are optional for DVD metadata and local inspection. This repository does not bundle third-party tools.

Copy the example configuration to the ignored local file:

```powershell
Copy-Item config/portable-disc-workflow.example.json config/local.json
```

Edit `config/local.json` before capture. Set `capture_root` and `inspection_root` to absolute local Windows paths. Set each archive `backup_root` to a separate destination. Set game `playable` fields to `{"host":"user@host.example","directory":"/absolute/library/gc"}` or the matching Wii path. Game filing requires SSH access and Python 3 on the target. Without a configured destination, the archive can remain verified while filing stays pending. Set installed executable paths under `tools`. Keep unused destinations and tools as `null`. The example contains no suppression rules.

## Check and run

From the repository folder, inspect one drive without capture first:

```powershell
python scripts/portable-disc-workflow.py --config config/local.json probe --drive E:
```

Review the identity and blockers. Then run the bundled launcher for one disc:

```powershell
.\start-ontherip.ps1 -Drive E:
```

For foreground watch mode, use:

```powershell
.\start-ontherip.ps1 -Drive E: -Watch
```

The launcher starts capture when a configured adapter matches. Exchange discs only after it reports that the drive is free. Stop watch mode with `Ctrl+C`.

## Supported scope

This release targets Windows DVD preservation and GameCube or Wii capture. It preserves guarded dry-probe and tool-hash checks. A configured PS3 tool can only open its GUI. The program does not verify PS3 capture completion. Blu-ray, Linux capture, continuous disc-swap acceptance, and automatic episode filing are not accepted.

A prior private pilot reported 15 of 15 DVD titles passing strict local audio/video checks. Those checks covered 51 audio/video streams. They did not prove subtitle completeness, every angle, correct episode mapping, or successful playback. That result does not prove acceptance for this sanitized public build or another computer. Run a dry probe before capture and review each result.

## Provenance

The public version is `0.1.0-dev.13-public.1`. `NOTICE.md` records source references, adaptations, and excluded third-party tools. The public tree contains generalized code only. It does not contain project history, test fixtures, sample payloads, or binaries.
