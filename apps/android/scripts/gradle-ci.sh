#!/usr/bin/env bash
# Runs ./gradlew in CI and turns Kotlin/AGP errors and failed tests into GitHub annotations,
# so a failure is readable from the run summary without opening the log.
set -uo pipefail
cd "$(dirname "$0")/.."
log="$(mktemp)"
./gradlew --console=plain "$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
  # Kotlin compiler: "e: file:///path/File.kt:12:5 message"
  sed -nE 's#^e: file://([^:]+):([0-9]+):([0-9]+) (.*)#::error file=\1,line=\2,col=\3::\4#p' "$log" | head -50
  # Android resource / manifest / lint errors: "/path/file.xml:12: Error: message"
  sed -nE 's#^(/[^:]+):([0-9]+):( [0-9]+:)? [Ee]rror: (.*)#::error file=\1,line=\2::\4#p' "$log" | head -50
  # Failed tests
  grep -E "^[A-Za-z0-9_.$]+ > .* FAILED$" "$log" | head -30 | sed 's/^/::error::/'
  # Gradle's summary
  awk '/^\* What went wrong:/{f=1;next} /^\* Try:/{f=0} f && NF' "$log" | head -20 | tr '\n' ' ' | sed 's/^/::error::Gradle: /'
  echo
fi
exit "$status"
