
mkdir build
meson --buildtype=plain --default-library static build
ninja -C build
$CXX $CXXFLAGS -std=c++11 -I.     $SRC/libspng/tests/spng_read_fuzzer.cc     -o $OUT/spng_read_fuzzer     $LIB_FUZZING_ENGINE $SRC/libspng/build/libspng.a -lz
$CXX $CXXFLAGS -std=c++11 -I.     $SRC/libspng/tests/spng_read_fuzzer.cc     -o $OUT/spng_read_fuzzer_structure_aware     -include ../fuzzer-test-suite/libpng-1.2.56/png_mutator.h     -D PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR     $LIB_FUZZING_ENGINE $SRC/libspng/build/libspng.a -lz
find $SRC/libspng/tests/images -name "*.png" |      xargs zip $OUT/spng_read_fuzzer_seed_corpus.zip
cp $SRC/libspng/tests/spng.dict    $SRC/libspng/tests/spng_read_fuzzer.options $OUT/
