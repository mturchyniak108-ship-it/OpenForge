#!/bin/sh

# Fast-build profile → tincc (object only)
if [ "$OCTO_PROFILE" = "fast" ]; then
    tincc -c "$1" -o "$1.o" || exit 1
    clang "$1.o" -o "$2" || exit 1
    exit 0
fi

# Debug profile → clang with symbols
if [ "$OCTO_PROFILE" = "debug" ]; then
    clang -g "$1" -o "$2"
    exit 0
fi

# Release profile → clang optimized
if [ "$OCTO_PROFILE" = "release" ]; then
    clang -O3 "$1" -o "$2"
    exit 0
fi

# Default → clang
clang "$1" -o "$2"
