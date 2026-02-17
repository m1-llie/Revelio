FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        gdb \
        cmake \
        meson \
        git \
        python3 \
        python3-pip \
        python3-venv \
        ninja-build \
        pkg-config \
        zlib1g-dev \
        valgrind \
        cppcheck \
        curl \
        vim \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# Create workspace and set default working directory
RUN mkdir -p /src
WORKDIR /src

# Default command is overridden by DockerEnvironment (sleep ...)
CMD ["/bin/bash"]
