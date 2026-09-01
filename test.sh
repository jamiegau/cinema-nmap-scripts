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

echo "Cinema NSE scripts validated successfully"
