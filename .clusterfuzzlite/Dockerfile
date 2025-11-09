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

# Copy build script
# Note: compile_python_fuzzer is already provided by the base image
COPY .clusterfuzzlite/build.sh $SRC/
