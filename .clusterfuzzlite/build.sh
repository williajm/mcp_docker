#!/bin/bash -eu
# Copyright 2025 MCP Docker Contributors
# Licensed under the Apache License, Version 2.0 (the "License");

# Build script for ClusterFuzzLite fuzz targets

# Install the project in development mode
python3 -m pip install -e $SRC/mcp-docker

# Build each fuzz target
for fuzzer in $SRC/mcp-docker/tests/fuzz/fuzz_*.py; do
    fuzzer_basename=$(basename -s .py "$fuzzer")
    fuzzer_name="${fuzzer_basename}"

    # Compile fuzzer using pyinstaller for better compatibility
    pyinstaller --onefile \
        --name "$fuzzer_name" \
        --distpath "$OUT" \
        --workpath "/tmp/$fuzzer_name" \
        --specpath "/tmp" \
        "$fuzzer"

    # If pyinstaller fails, fall back to direct copy
    if [ ! -f "$OUT/$fuzzer_name" ]; then
        echo "PyInstaller failed for $fuzzer_name, using direct copy"
        cp "$fuzzer" "$OUT/$fuzzer_name"
        chmod +x "$OUT/$fuzzer_name"

        # Add shebang if needed
        sed -i '1i#!/usr/bin/env python3' "$OUT/$fuzzer_name"
    fi
done

echo "Fuzz targets built successfully:"
ls -lh "$OUT"/fuzz_*
