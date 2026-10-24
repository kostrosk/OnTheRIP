# OnTheRIP

A small disc-preservation workflow for keeping verified copies under your control.

## Why this exists

Some discs never reach a streaming catalog. Obscure films, DVD extras, and older games can disappear when the last readable copy fails. OnTheRIP aims to make preservation a routine you can repeat.

This project uses "data autonomy L2" as shorthand for keeping verified copies you control. It is a project phrase, not a recognized certification.

## The planned workflow

Start the configured program and leave it open. Insert a disc. Exchange physical discs by hand when the program says the drive is free. It identifies the disc from evidence, selects a matching supported tool, and records that tool's actual completion. It copies the archive to network storage, also called a NAS. It rereads the copied files and compares their SHA-256 fingerprints to detect changed bytes.

Next, it copies the verified result to the configured playable destination and compares SHA-256 fingerprints there. It reports the completed stage before the next disc starts. An unknown year or episode does not block an archive. The process must not guess a final television episode mapping.

## Walkthrough states

**Archive verified, metadata pending** means the archive and its verified NAS copy exist, but the title or episode mapping still needs evidence. The archive can wait in this state.

**Fully filed** means the archive, NAS backup, and configured playable copy passed their checks, and the available metadata supports the filing. A notification must describe the stage that actually finished.

## What has passed so far

Windows pilots verified automatic GameCube archiving, followed by a playable copy over secure shell (SSH), a hash check, and a visible notice. Two complete DVD archives passed independent NAS hash checks.

A DVD extraction saved fifteen titles, including short extras. Strict local verification remains pending. Continuous disc swaps and Linux still need live pilots. Blu-ray, final movie and television filing, and playback remain unverified. These results do not support a claim that every disc format works.

## Project status

This public repository contains a walkthrough. The implementation remains private and experimental. There is no downloadable package or installation command here.

Star OnTheRIP to follow the preservation pilots and the path toward a simpler disc workflow.
