# OnTheRIP

A simpler media-preservation process. Keep our history before the last readable disc disappears.

Some discs never reach a streaming catalog. Obscure films, DVD extras, and older games deserve copies that their owners can keep and check.

OnTheRIP connects existing tools into one foreground workflow. The goal is simple: start the program, insert a disc, and exchange discs when it reports completion.

## The workflow

1. Identify the disc from measured evidence.
2. Select a supported capture tool.
3. Check the tool's completion and retained output.
4. Copy the archive to network storage, also called a NAS.
5. Reread the archive and compare SHA-256 hashes, which detect changed bytes.
6. Prepare the configured playable copy and check its destination hash.
7. Report what finished and what still needs attention.

An unknown title, year, or episode does not stop preservation. It does stop an unsupported final name or episode assignment.

## Repeat the process

The private pilot uses a PowerShell launcher with a configured release, storage paths, and installed media tools.
This repository does not distribute that launcher or the implementation. These examples describe its interface, not an installation procedure.

On a configured Windows computer, in PowerShell, from the folder that contains the private launcher:

```powershell
.\start-ontherip.ps1 -Drive 'E:'
```

This command processes one disc through the configured workflow.
A failed or unsupported stage reports its cause. Inspect that result before another attempt.

For the intended continuous foreground workflow, the launcher also accepts:

```powershell
.\start-ontherip.ps1 -Drive 'E:' -Watch
```

Continuous physical-disc swaps still need acceptance tests. Keep the window open and follow the reported drive status.

## Results and limits

Windows pilots passed automatic GameCube capture, NAS verification, and a separate verified playable copy with a visible notification.
Two full DVD archives passed independent checks of every archived file's size and SHA-256 hash.

A DVD extraction retained fifteen titles, including short material. All fifteen existing files passed strict local audio/video decode and packet checks.
Those checks covered 51 audio/video streams. They do not prove subtitle completeness, every angle, correct episode names, or successful playback.

DVD episode mapping and final Jellyfin library placement remain pending. Linux, Blu-ray, continuous swaps, and universal format support remain unproven.
An archive ISO is not a claim of decryption or Jellyfin playback support.

## What the notices mean

**Archive verified; metadata pending** means preservation passed, but identification or playable placement remains incomplete.

**Fully filed** means every required destination passed its hash checks and the evidence supports the final names.
Playback acceptance remains a separate check.

## Project status

The implementation and operational details remain private on Forgejo. This public repository contains only this walkthrough.
There is no downloadable package here yet.

"Data autonomy L2" is our project phrase for verified copies under your control, not a certification.
Star OnTheRIP to follow the pilots and the path toward a simpler preservation workflow.
