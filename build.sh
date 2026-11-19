#!/usr/bin/env bash
# Compile and test the network scanner on Linux/macOS.
# Usage:  ./build.sh                       -> compile + run tests
#         ./build.sh scan <target> [opts]  -> compile + scan (authorised networks only)
set -euo pipefail
rm -rf out
javac --release 17 -Xlint:all -d out $(find src -name "*.java")
if [ "${1:-}" = "scan" ]; then
  shift
  java -cp out netscan.NetScanApp "$@"
else
  java -cp out netscan.NetScanTest
fi
