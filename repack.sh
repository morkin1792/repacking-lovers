#!/bin/sh
set -eu
cd -- "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else "Python 3.11 or newer is required")'
exec python3 -m repack "$@"
