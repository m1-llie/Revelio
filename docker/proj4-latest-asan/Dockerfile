FROM vulagent/proj4-asan:latest

# Clone the latest PROJ main branch
RUN git clone --depth 1 https://github.com/OSGeo/PROJ /src/PROJ-latest && \
    git -C /src/PROJ-latest rev-parse HEAD > /PROJ_LATEST_COMMIT && \
    cat /PROJ_LATEST_COMMIT

# Build with ASan (same flags as the existing proj4-asan image)
RUN mkdir -p /proj4-latest-build && cd /proj4-latest-build && \
    cmake /src/PROJ-latest \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_APPS=OFF \
        -DBUILD_TESTING=OFF \
        -DENABLE_TIFF=OFF \
        -DENABLE_CURL=OFF \
        -DCMAKE_C_FLAGS='-fsanitize=address -g -O1' \
        -DCMAKE_CXX_FLAGS='-fsanitize=address -g -O1' \
        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DSQLite3_INCLUDE_DIR=/usr/include \
        -DSQLite3_LIBRARY=/usr/lib/x86_64-linux-gnu/libsqlite3.so.0 && \
    make -j$(nproc) -s && \
    echo "Build OK" && ls /proj4-latest-build/lib/
