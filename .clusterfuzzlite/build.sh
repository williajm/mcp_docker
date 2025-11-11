#!/bin/bash -eu

# Build script for ClusterFuzzLite fuzz targets

# Install the project in development mode with proper flags
# Note: The project itself is installed in editable mode from local source,
# not from a package repository, so version pinning is not applicable here.
# All external dependencies are pinned in Dockerfile and pyproject.toml.
pip3 install --no-deps -e $SRC/mcp-docker

# PyInstaller hidden imports for dependencies not auto-detected
# These are third-party libraries used by the auth/security modules
export PYINSTALLER_HIDDEN_IMPORTS="limits,limits.aio,limits.aio.strategies,limits.aio.storage,cachetools,loguru"

# Build each fuzz target using the compile_python_fuzzer helper
for fuzzer in $SRC/mcp-docker/tests/fuzz/fuzz_*.py; do
    echo "Compiling fuzzer: $(basename $fuzzer)"
    compile_python_fuzzer "$fuzzer" -- \
        --hidden-import=limits \
        --hidden-import=limits.aio \
        --hidden-import=limits.aio.strategies \
        --hidden-import=limits.aio.storage \
        --hidden-import=cachetools \
        --hidden-import=loguru
done

echo "Fuzz targets built successfully:"
ls -lh "$OUT"/fuzz_*
