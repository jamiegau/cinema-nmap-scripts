#!/bin/sh

set -eu

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
else
	echo "Lua not installed; CP850 offline behaviour tests skipped" >&2
fi

echo "Cinema NSE scripts validated successfully"
