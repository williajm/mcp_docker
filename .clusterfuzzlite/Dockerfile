FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:122afa48603810a0c6b495ab2e1cfdc5a88e4378ab051d3a83f666bd69b4eb0b

# Note: This image provides Python 3.11.13 with pip 25.3 and all OSS-Fuzz infrastructure
# Environment variables $SRC and $OUT are already set by the base image

# Copy project files
COPY . $SRC/mcp-docker
WORKDIR $SRC/mcp-docker

# Install Python dependencies with cryptographic hash verification
# The base image has pip 25.3 which supports --require-hashes
# Note: --hash option only works in requirements files, not on command line
RUN python3 -m pip install --require-hashes --no-deps -r .clusterfuzzlite/requirements.txt && \
    python3 -m pip install --no-deps -e .

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
