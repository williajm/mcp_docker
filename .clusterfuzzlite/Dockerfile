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
# Download and verify pip wheel with hash before installing
RUN wget -q https://files.pythonhosted.org/packages/ef/7d/500c9ad20238fcfcb4cb9243eede163594d7020ce87bd9610c9e02771876/pip-24.3.1-py3-none-any.whl && \
    echo "3790624780082365f47549d032f3770eeb2b1e8bd1f7b2e02dace1afa361b4ed  pip-24.3.1-py3-none-any.whl" | sha256sum -c && \
    python3 -m pip install pip-24.3.1-py3-none-any.whl && \
    rm pip-24.3.1-py3-none-any.whl && \
    python3 -m pip install --require-hashes --no-deps -r .clusterfuzzlite/requirements.txt && \
    python3 -m pip install --no-deps -e .

# Copy build script
COPY .clusterfuzzlite/build.sh $SRC/
