#!/bin/bash -eu

# Build script for ClusterFuzzLite fuzz targets

# Install the project in development mode with proper flags
pip3 install -e $SRC/mcp-docker

# Build each fuzz target using the compile_python_fuzzer helper
for fuzzer in $SRC/mcp-docker/tests/fuzz/fuzz_*.py; do
    echo "Compiling fuzzer: $(basename $fuzzer)"
    compile_python_fuzzer "$fuzzer"
done

echo "Fuzz targets built successfully:"
ls -lh "$OUT"/fuzz_*
