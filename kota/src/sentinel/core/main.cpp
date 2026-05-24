/*
 * kotad — KOTA Community Edition process entry (thin).
 *
 * Runtime: kotad_runtime.cpp (docs/flow.md phases).
 */

#include "kotad_runtime.h"

#include <utility>

int main(int argc, char **argv)
{
    kota::KotadCliOptions cli{};
    switch (kota::parse_kotad_cli(argc, argv, cli)) {
    case kota::KotadCliParse::Help:
        kota::print_kotad_help(argv[0]);
        return 0;
    case kota::KotadCliParse::Error:
        kota::print_kotad_help(argv[0]);
        return 2;
    case kota::KotadCliParse::Ok:
        break;
    }

    kota::KotadRuntime app{std::move(cli)};
    return app.run();
}
