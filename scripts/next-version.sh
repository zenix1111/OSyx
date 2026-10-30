#!/bin/bash
# Prints the version the next OSyx release should carry.
#
# The highest vX.Y.Z tag defines the line: the next release is that patch
# plus one. VERSION only overrides the line: when it names a newer
# major.minor than the highest tag (e.g. 0.2.0 after 0.1.5), that version is
# released next and later releases continue 0.2.1, 0.2.2, ...
#
#   scripts/next-version.sh        (prints e.g. 0.1.6)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
git fetch --tags --force --quiet origin 2>/dev/null || true
latest="$(git tag --list 'v[0-9]*' --sort=-v:refname | head -n1)"
file="$(tr -d ' \r\n' < VERSION)"
exec python3 - "$latest" "$file" <<'PY'
import re
import sys

latest, version = sys.argv[1], sys.argv[2]


def parts(value):
    value = value.lstrip("v")
    if not re.fullmatch(r"\d+(\.\d+)*", value):
        sys.exit(f"next-version: {value or 'VERSION'} is not a version")
    numbers = [int(part) for part in value.split(".")]
    return numbers + [0] * (3 - len(numbers))


file_version = parts(version)
if not latest:
    print(".".join(map(str, file_version[:3])))
else:
    tag = parts(latest)
    if (file_version[0], file_version[1]) > (tag[0], tag[1]):
        print(".".join(map(str, file_version[:3])))
    else:
        print(f"{tag[0]}.{tag[1]}.{tag[2] + 1}")
PY
