#!/bin/bash -eu
# Copyright 2025 MCP Docker Contributors
# Licensed under the Apache License, Version 2.0 (the "License");

# Build script for ClusterFuzzLite fuzz targets

# Install the project in development mode with proper flags
pip3 install -e $SRC/mcp-docker

# Build each fuzz target following ClusterFuzzLite Python conventions
for fuzzer in $SRC/mcp-docker/tests/fuzz/fuzz_*.py; do
    fuzzer_basename=$(basename -s .py "$fuzzer")
    fuzzer_package="${fuzzer_basename}.pkg"

    echo "Building fuzzer: $fuzzer_basename"

    # Create standalone package using pyinstaller
    pyinstaller --distpath "$OUT" --onefile --name "$fuzzer_package" "$fuzzer"

    # Create execution wrapper (required by ClusterFuzzLite)
    # Note: No LD_PRELOAD needed since we're fuzzing Python-only code without C extensions
    cat > "$OUT/$fuzzer_basename" << EOF
#!/bin/sh
# Wrapper script for ClusterFuzzLite fuzzer execution
this_dir=\$(dirname "\$0")
"\$this_dir/$fuzzer_package" "\$@"
EOF
    chmod +x "$OUT/$fuzzer_basename"
done

echo "Fuzz targets built successfully:"
ls -lh "$OUT"/fuzz_*
