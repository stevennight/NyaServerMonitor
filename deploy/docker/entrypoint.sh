#!/bin/sh
set -eu

data_dir="${NYASM_DATA:-/data}"
mkdir -p "$data_dir"
chown -R nyasm:nyasm "$data_dir"

exec su-exec nyasm /usr/local/bin/nyasm-controller "$@"
