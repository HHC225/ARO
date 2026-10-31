#!/usr/bin/env bash
# Keep all argument boundaries intact; never evaluate discovered text.
set -euo pipefail
aro_script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
  exec python3 "$aro_script_dir/aro.py" "$@"
fi
if command -v python >/dev/null 2>&1; then
  exec python "$aro_script_dir/aro.py" "$@"
fi
printf '%s\n' 'ARO requires Python 3.11 or newer. Install it and retry.' >&2
exit 2
