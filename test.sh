#!/bin/sh

set -eu

case "${1-}" in
    ""|--loopback) ;;
    *) echo "Usage: $0 [--loopback]" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if command -v luac >/dev/null 2>&1; then
	for script_path in "$script_dir"/cinema-*.nse; do
		luac -p "$script_path"
	done
fi

if ! command -v nmap >/dev/null 2>&1; then
	echo "nmap is required to validate the NSE scripts" >&2
	exit 1
fi

# --script-help loads and compiles every script without scanning a network.
nmap --script-help "$script_dir/" >/dev/null

if command -v lua >/dev/null 2>&1; then
	lua "$script_dir/tests/cp850.lua" "$script_dir"
	lua "$script_dir/tests/cp950.lua" "$script_dir"
	lua "$script_dir/tests/barco-player.lua" "$script_dir"
	lua "$script_dir/tests/projectors.lua" "$script_dir"
	lua "$script_dir/tests/christie.lua" "$script_dir"
	lua "$script_dir/tests/senior.lua" "$script_dir"
else
	echo "Lua not installed; offline behaviour tests skipped" >&2
fi

if [ "${1-}" = "--loopback" ]; then
    python3 "$script_dir/tests/christie-loopback.py"
    python3 "$script_dir/tests/cp950-loopback.py"
    python3 "$script_dir/tests/senior-loopback.py"
    python3 "$script_dir/tests/dolby-player-loopback.py"
    python3 "$script_dir/tests/barco-player-loopback.py"
fi

echo "Cinema NSE scripts validated successfully"
