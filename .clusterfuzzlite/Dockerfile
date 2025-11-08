FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:122afa48603810a0c6b495ab2e1cfdc5a88e4378ab051d3a83f666bd69b4eb0b

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . $SRC/mcp-docker
WORKDIR $SRC/mcp-docker

# Install Python dependencies with cryptographic hash verification
# Pin pip to a specific version for reproducibility
RUN python3 -m pip install --upgrade pip==24.3.1 && \
    python3 -m pip install --require-hashes --no-deps -r .clusterfuzzlite/requirements.txt && \
    python3 -m pip install -e .

# Copy build script
COPY .clusterfuzzlite/build.sh $SRC/
