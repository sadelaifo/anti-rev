// json_trace — LD_PRELOAD shim that intercepts
//   google::protobuf::util::JsonStringToMessage(...)
// and prints, on each call, whether the Message's descriptor came
// from the SAME DescriptorPool as generated_pool(), before chaining
// to the real libprotobuf implementation.
//
// Why this exists:
//   After antirev packing, some C++ components fail with
//   "json transcoder produced invalid protobuf output". Single-pool
//   has been verified (one libprotobuf, no static embedding), so
//   the remaining question is whether message.GetDescriptor() at
//   runtime actually points into generated_pool, or into a separate
//   runtime-built DescriptorPool.
//
// Build (on aarch64 target, where libprotobuf headers match the
// broken binary's):
//
//   g++ -O2 -fPIC -shared -std=c++17 \
//       -o json_trace.so json_trace.cc -ldl -lprotobuf
//
// Usage:
//   LD_PRELOAD=/path/to/json_trace.so:$LD_PRELOAD ./your.broken.cmd
//
//   (If the broken process is already launched via antirev stub,
//    prepend json_trace.so to LD_PRELOAD in the environment that
//    launches the stub — the stub inherits LD_PRELOAD, and our .so
//    stays loaded in the owner process alongside exe_shim.)
//
// Expected output per call (STDERR):
//   [json_trace] gen_pool=0xAAA msg_pool=0xBBB same=NO desc=<full.name>
//
// Interpretation:
//   - same=YES  => message descriptor lives in generated_pool. The
//                  "invalid protobuf output" bug is NOT a pool mismatch.
//                  Look at ctor ordering / gRPC transcoder internals.
//   - same=NO   => message descriptor lives in a DIFFERENT pool (most
//                  likely one built at runtime from a .desc file).
//                  JsonStringToMessage defaults to generated_pool for
//                  type lookup, so fields won't match. Fix is to pass
//                  a TypeResolver built from the runtime pool, OR to
//                  check whether the .desc loading path is broken by
//                  realpath/readlink interception.

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>

namespace gpb = google::protobuf;
namespace gpu = google::protobuf::util;

namespace {

// Resolved lazily via dladdr on ourselves + dlsym(RTLD_NEXT, ...).
// This avoids hardcoding any mangled name — the compiler produces
// whatever mangling matches the installed protobuf headers, and
// libprotobuf.so.* exports the same one.
//
// NOTE: we only override the 3-arg overload. In protobuf >= ~3.21
// the 2-arg JsonStringToMessage is an inline wrapper in the header
// that forwards to the 3-arg, so redefining it here triggers an
// "inline function redefined" error. All call sites that use the
// 2-arg form get inlined to 3-arg at the caller's compile time, so
// the 3-arg interceptor catches them anyway.
using Fn3 = gpu::Status (*)(gpb::StringPiece, gpb::Message *,
                            const gpu::JsonParseOptions &);

static Fn3 real3 = nullptr;

static void *resolve_next(void *self_fn_addr) {
    Dl_info info;
    if (!dladdr(self_fn_addr, &info) || !info.dli_sname) {
        fprintf(stderr, "[json_trace] dladdr failed\n");
        return nullptr;
    }
    void *next = dlsym(RTLD_NEXT, info.dli_sname);
    if (!next) {
        fprintf(stderr, "[json_trace] dlsym RTLD_NEXT %s: %s\n",
                info.dli_sname, dlerror());
    }
    return next;
}

static void print_diag(const gpb::Message *message, const char *variant) {
    const gpb::DescriptorPool *gen_pool = gpb::DescriptorPool::generated_pool();
    const gpb::Descriptor *desc = message ? message->GetDescriptor() : nullptr;
    const gpb::DescriptorPool *msg_pool =
        desc ? desc->file()->pool() : nullptr;

    fprintf(stderr,
            "[json_trace/%s] gen_pool=%p msg_pool=%p same=%s desc=%s\n",
            variant,
            (const void *)gen_pool,
            (const void *)msg_pool,
            (gen_pool == msg_pool) ? "YES" : "NO",
            desc ? desc->full_name().c_str() : "(null)");
    fflush(stderr);
}

}  // namespace

namespace google {
namespace protobuf {
namespace util {

Status JsonStringToMessage(StringPiece input, Message *message,
                           const JsonParseOptions &options) {
    if (!real3) {
        Status (*self)(StringPiece, Message *, const JsonParseOptions &) =
            &JsonStringToMessage;
        real3 = (Fn3)resolve_next((void *)self);
    }
    print_diag(message, "3arg");
    if (!real3) {
        fprintf(stderr, "[json_trace] FATAL: no real JsonStringToMessage/3\n");
        abort();
    }
    return real3(input, message, options);
}

}  // namespace util
}  // namespace protobuf
}  // namespace google
