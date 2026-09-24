// Minimal reproducer for the packed-binary "json transcoder produced
// invalid protobuf output" failure.
//
// Mirrors what the business code does:
//   1. read a .config file as a string
//   2. call JsonStringToMessage into a nested+map message
//   3. print a stable textual summary
//
// Same binary runs both plain and packed. If outputs diverge, antirev
// has broken the JSON->Message path and we have a tight debug loop.

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/util/json_util.h>

#include "foo.pb.h"

int main(int argc, char** argv) {
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    const char* path = (argc > 1) ? argv[1] : "data.config";

    std::ifstream f(path);
    if (!f) {
        std::cerr << "FAIL: cannot open " << path << "\n";
        return 2;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string json = ss.str();

    // Pool diagnostics — prints once regardless of pass/fail.
    const auto* gen_pool = google::protobuf::DescriptorPool::generated_pool();
    const auto* desc     = diag::Config::descriptor();
    const auto* msg_pool = desc->file()->pool();
    std::cerr << "[diag] gen_pool=" << gen_pool
              << " msg_pool=" << msg_pool
              << " same=" << (gen_pool == msg_pool ? "YES" : "NO")
              << " desc=" << desc->full_name() << "\n";

    diag::Config cfg;
    auto st = google::protobuf::util::JsonStringToMessage(json, &cfg);
    if (!st.ok()) {
        std::cerr << "FAIL JsonStringToMessage: " << st.ToString() << "\n";
        return 3;
    }

    // Stable, sorted output so plain vs packed can diff cleanly.
    std::cout << "id=" << cfg.id() << "\n";
    std::cout << "meta.name=" << cfg.meta().name()
              << " count=" << cfg.meta().count()
              << " vals=" << cfg.meta().vals_size() << "\n";
    std::cout << "items.size=" << cfg.items().size() << "\n";
    // map iteration is unordered — copy into vector and sort.
    std::vector<std::string> keys;
    for (const auto& kv : cfg.items()) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end());
    for (const auto& k : keys) {
        const auto& v = cfg.items().at(k);
        std::cout << "  item[" << k << "] name=" << v.name()
                  << " count=" << v.count()
                  << " vals=" << v.vals_size() << "\n";
    }
    std::cout << "tags.size=" << cfg.tags_size() << "\n";
    std::cout << "labels.size=" << cfg.labels().size() << "\n";
    std::vector<int32_t> lkeys;
    for (const auto& kv : cfg.labels()) lkeys.push_back(kv.first);
    std::sort(lkeys.begin(), lkeys.end());
    for (int32_t k : lkeys) {
        std::cout << "  label[" << k << "]=" << cfg.labels().at(k) << "\n";
    }
    std::cout << "OK\n";
    return 0;
}
