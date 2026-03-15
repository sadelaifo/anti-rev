#!/usr/bin/env python3
"""
bench/gen.py — generate bench/project/ synthetic C benchmark
"""
import os
import sys

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "project")
SRC  = os.path.join(BASE, "src")
BUILD_DIR = os.path.join(BASE, "build")

N_MODULES = 500

def make_module(i):
    tag = f"{i:04d}"
    lines = [
        '#include <stdio.h>',
        '#include <string.h>',
        '#include <stdlib.h>',
        '',
        f'static long fib_{tag}(int n) {{',
        '    if (n <= 1) return n;',
        '    long a = 0, b = 1;',
        '    for (int i = 2; i <= n; i++) { long c = a + b; a = b; b = c; }',
        '    return b;',
        '}',
        '',
        f'static void xform_{tag}(unsigned char *buf, int len) {{',
        f'    unsigned char key = (unsigned char)({i} & 0xFF);',
        '    for (int i = 0; i < len; i++) {',
        f'        buf[i] ^= key;',
        f'        buf[i] = (unsigned char)((buf[i] << 1) | (buf[i] >> 7));',
        f'        buf[i] += (unsigned char)({i % 17});',
        '    }',
        '}',
        '',
        f'static long checksum_{tag}(const unsigned char *buf, int len) {{',
        '    long h = 0x12345678L;',
        '    for (int i = 0; i < len; i++) {',
        f'        h = (h ^ buf[i]) * 1000003L + {i % 97 + 1};',
        '    }',
        '    return h;',
        '}',
        '',
        f'static void isort_{tag}(int *arr, int n) {{',
        '    for (int i = 1; i < n; i++) {',
        '        int key = arr[i];',
        '        int j = i - 1;',
        '        while (j >= 0 && arr[j] > key) { arr[j+1] = arr[j]; j--; }',
        '        arr[j+1] = key;',
        '    }',
        '}',
        '',
        f'void module_run_{tag}(void) {{',
        f'    long f = fib_{tag}(30 + ({i} % 10));',
        '    unsigned char buf[64];',
        f'    for (int k = 0; k < 64; k++) buf[k] = (unsigned char)((k * {i+1}) & 0xFF);',
        f'    xform_{tag}(buf, 64);',
        f'    long cs = checksum_{tag}(buf, 64);',
        '    int arr[16];',
        f'    for (int k = 0; k < 16; k++) arr[k] = (16 - k) * {i+1 % 7 + 1};',
        f'    isort_{tag}(arr, 16);',
        f'    printf("mod {tag}: fib=%ld cs=%ld arr[0]=%d\\n", f, cs, arr[0]);',
        '}',
    ]
    return '\n'.join(lines) + '\n'

def make_main():
    # forward declarations
    decls = '\n'.join(f'void module_run_{i:04d}(void);' for i in range(N_MODULES))
    return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

{decls}

#define N_WORKERS 8
#define N_MODULES {N_MODULES}

static double now_sec(void) {{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}}

int main(void) {{
    const char *worker = getenv("WORKER");
    if (!worker) worker = "./worker_bin";

    /* Call first 20 modules ourselves */
    printf("[main] calling first 20 modules\\n");
    module_run_0000(); module_run_0001(); module_run_0002(); module_run_0003();
    module_run_0004(); module_run_0005(); module_run_0006(); module_run_0007();
    module_run_0008(); module_run_0009(); module_run_0010(); module_run_0011();
    module_run_0012(); module_run_0013(); module_run_0014(); module_run_0015();
    module_run_0016(); module_run_0017(); module_run_0018(); module_run_0019();

    double t0 = now_sec();

    /* Fork N_WORKERS children */
    int per_worker = N_MODULES / N_WORKERS;
    pid_t pids[N_WORKERS];
    for (int w = 0; w < N_WORKERS; w++) {{
        int start = w * per_worker;
        int count = (w == N_WORKERS-1) ? (N_MODULES - start) : per_worker;
        char s_start[16], s_count[16];
        snprintf(s_start, sizeof(s_start), "%d", start);
        snprintf(s_count, sizeof(s_count), "%d", count);
        pid_t pid = fork();
        if (pid == 0) {{
            execlp(worker, worker, s_start, s_count, NULL);
            perror("execlp"); _exit(1);
        }}
        if (pid < 0) {{ perror("fork"); return 1; }}
        pids[w] = pid;
    }}

    for (int w = 0; w < N_WORKERS; w++) {{
        int status;
        waitpid(pids[w], &status, 0);
    }}

    double elapsed = now_sec() - t0;
    printf("[main] all workers done in %.3f s\\n", elapsed);
    return 0;
}}
'''

def make_worker():
    decls = '\n'.join(f'void module_run_{i:04d}(void);' for i in range(N_MODULES))
    return f'''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

{decls}

typedef void (*mod_fn)(void);
static mod_fn module_table[{N_MODULES}] = {{
''' + ',\n'.join(f'    module_run_{i:04d}' for i in range(N_MODULES)) + '''
};

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: worker <start> <count>\\n");
        return 1;
    }
    int start = atoi(argv[1]);
    int count = atoi(argv[2]);
    int end   = start + count;
    if (end > ''' + str(N_MODULES) + ''') end = ''' + str(N_MODULES) + ''';

    char logpath[64];
    snprintf(logpath, sizeof(logpath), "/tmp/worker_%d.log", (int)getpid());
    FILE *logf = fopen(logpath, "w");
    if (!logf) logf = stderr;

    for (int i = start; i < end; i++) {
        /* redirect stdout to log */
        fprintf(logf, "[worker pid=%d] running module %04d\\n", (int)getpid(), i);
        module_table[i]();
    }
    if (logf != stderr) fclose(logf);
    return 0;
}
'''

def make_makefile():
    mod_objs = ' '.join(f'build/module_{i:04d}.o' for i in range(N_MODULES))
    mod_rules = '\n'.join(
        f'build/module_{i:04d}.o: src/module_{i:04d}.c | build\n\t$(CC) $(CFLAGS) -c $< -o $@'
        for i in range(N_MODULES)
    )
    return f'''CC = gcc
CFLAGS = -O2 -Wall

MOD_OBJS = {mod_objs}

all: main_bin worker_bin

build:
\tmkdir -p build

bigdata.bin:
\tpython3 -c "open('bigdata.bin','wb').write(bytes(i%251 for i in range(100*1024*1024)))"

bigdata.o: bigdata.bin
\tobjcopy -I binary -O elf64-x86-64 -B i386 bigdata.bin bigdata.o

build/main.o: src/main.c | build
\t$(CC) $(CFLAGS) -c $< -o $@

build/worker.o: src/worker.c | build
\t$(CC) $(CFLAGS) -c $< -o $@

{mod_rules}

main_bin: $(MOD_OBJS) build/main.o bigdata.o
\t$(CC) $(CFLAGS) -o $@ $^

worker_bin: $(MOD_OBJS) build/worker.o
\t$(CC) $(CFLAGS) -o $@ $^

clean:
\trm -rf build main_bin worker_bin bigdata.bin bigdata.o

.PHONY: all clean
'''

def main():
    os.makedirs(SRC, exist_ok=True)
    os.makedirs(BUILD_DIR, exist_ok=True)

    print(f"[gen] Generating {N_MODULES} module files...")
    for i in range(N_MODULES):
        path = os.path.join(SRC, f"module_{i:04d}.c")
        with open(path, 'w') as f:
            f.write(make_module(i))
        if i % 100 == 0:
            print(f"  ... {i}/{N_MODULES}")

    print("[gen] Writing main.c...")
    with open(os.path.join(SRC, "main.c"), 'w') as f:
        f.write(make_main())

    print("[gen] Writing worker.c...")
    with open(os.path.join(SRC, "worker.c"), 'w') as f:
        f.write(make_worker())

    print("[gen] Writing Makefile...")
    with open(os.path.join(BASE, "Makefile"), 'w') as f:
        f.write(make_makefile())

    print(f"[gen] Done. Project at: {BASE}")
    print(f"[gen] Build with: cd {BASE} && make -j$(nproc)")

if __name__ == "__main__":
    main()
