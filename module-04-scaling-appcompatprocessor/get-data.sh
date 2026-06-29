#!/usr/bin/env sh
# get-data.sh (Module 4) — add more HOSTS so stacking/LFO becomes meaningful.
#
# Stacking's payoff scales with host count. This lab bundles ONE fully-documented
# host (Case 001 / DESKTOP-SDN1RPT) so the exercise has verifiable answers. To feel
# Least-Frequency-of-Occurrence work, add the parsed Triad artifacts from more hosts.
#
# There is no single public "multi-host Amcache" download, so this is a recipe, not a
# fetch. On each additional host's collected hives, run the same EZ tools you used in
# Modules 2-3, then drop the CSVs here following the naming convention below.
#
# Naming convention (so the host is identifiable):
#   data/amcache_host-<NAME>_UnassociatedFileEntries.csv   (and the other AmcacheParser CSVs)
#   data/shimcache_host-<NAME>.csv
#
# Generate them (inside dfir-aio:v2) from a host's collected hives:
#   AmcacheParser       -f /in/Amcache.hve --csv /out --csvf amcache_host-<NAME>.csv -i
#   AppCompatCacheParser -f /in/SYSTEM     --csv /out --csvf shimcache_host-<NAME>.csv
#
# Then re-run Part 1's awk recipes (or, on a host with a working AppCompatProcessor
# install, `AppCompatProcessor.py hosts.db load ./data` then `stack`). With >1 host the
# Count column finally separates ubiquitous Microsoft binaries from the rare attacker tool.
#
# Provenance of the bundled host: DFIR Madness "Case 001" disk image (a documented intrusion).
set -eu
echo "Module 4 uses pre-parsed Triad CSVs. See the comments in this file to ADD hosts."
echo "Bundled host: DESKTOP-SDN1RPT (DFIR Madness Case 001)."
ls -1 "$(cd "$(dirname "$0")" && pwd)/data" 2>/dev/null
