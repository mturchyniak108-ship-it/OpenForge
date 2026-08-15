#!/bin/sh
# Octo rsync partial pull: OneDrive → local (no deletes)

SRC="$HOME/OneDrive/OctoBackup/"
DST="$HOME/octo-src/"

rsync -av "$SRC" "$DST"
