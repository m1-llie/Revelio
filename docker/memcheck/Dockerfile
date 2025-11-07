FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        gdb \
        cmake \
        git \
        python3 \
        python3-pip \
        python3-venv \
        ninja-build \
        pkg-config \
        valgrind \
        curl \
        vim \
    && rm -rf /var/lib/apt/lists/*

# Create workspace and set default working directory
RUN mkdir -p /workspace
WORKDIR /workspace

# Install pip packages commonly needed for tooling (optional)
RUN pip3 install --no-cache-dir \
    litellm==1.75.5 \
    pytest==8.2.0

# Default command is overridden by DockerEnvironment (sleep ...)
CMD ["/bin/bash"]
