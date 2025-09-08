#!/bin/sh

extra_args=""
if [ "${1:-}" = "all" ]; then
  extra_args="--target-version 0"
fi

cargo sqlx migrate revert $extra_args
