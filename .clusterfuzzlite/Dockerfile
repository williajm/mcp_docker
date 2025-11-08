FROM gcr.io/oss-fuzz-base/base-builder-python

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . $SRC/mcp-docker
WORKDIR $SRC/mcp-docker

# Install Python dependencies including atheris for fuzzing
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install atheris && \
    python3 -m pip install -e . && \
    python3 -m pip install pydantic pydantic-settings loguru cryptography

# Copy build script
COPY .clusterfuzzlite/build.sh $SRC/
