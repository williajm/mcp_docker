FROM python:3.14-slim

# Set up OSS-Fuzz environment variables expected by build.sh
ENV SRC=/src
ENV OUT=/out

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create OSS-Fuzz directories
RUN mkdir -p $SRC $OUT

# Copy project files
COPY . $SRC/mcp-docker
WORKDIR $SRC/mcp-docker

# Install Python dependencies with cryptographic hash verification
# Python 3.14 comes with modern pip that supports --require-hashes
RUN python3 -m pip install --require-hashes --no-deps \
        pip==24.3.1 \
        --hash=sha256:3790624780082365f47549d032f3770eeb2b1e8bd1f7b2e02dace1afa361b4ed && \
    python3 -m pip install --require-hashes --no-deps -r .clusterfuzzlite/requirements.txt && \
    python3 -m pip install --no-deps -e .

# Install Atheris for fuzzing
RUN python3 -m pip install atheris

# Create compile_python_fuzzer helper function (OSS-Fuzz compatibility)
RUN echo '#!/bin/bash\n\
# Simple compile_python_fuzzer stub for ClusterFuzzLite\n\
# In OSS-Fuzz, this would do more complex compilation\n\
# For our purposes, we just copy the fuzzer to $OUT\n\
fuzzer_path="$1"\n\
fuzzer_name=$(basename "$fuzzer_path" .py)\n\
cp "$fuzzer_path" "$OUT/$fuzzer_name"\n\
chmod +x "$OUT/$fuzzer_name"\n\
' > /usr/local/bin/compile_python_fuzzer && \
    chmod +x /usr/local/bin/compile_python_fuzzer

# Copy build script
COPY .clusterfuzzlite/build.sh $SRC/
