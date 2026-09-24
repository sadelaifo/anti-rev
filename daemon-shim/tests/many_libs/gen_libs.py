#!/usr/bin/env python3
"""Generate N trivial .c files for the many_libs stress test.

Usage: gen_libs.py <output_dir> <N>

Generates:
  libstress_01.c .. libstress_NN.c  (each exports stress_NN_func)
  main.c                            (calls all of them)
"""
import sys
from pathlib import Path

def main():
    outdir = Path(sys.argv[1])
    n = int(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)

    # Generate lib source files
    for i in range(1, n + 1):
        name = f"libstress_{i:02d}"
        src = outdir / f"{name}.c"
        src.write_text(
            f"int stress_{i:02d}_func(int x) {{ return x + {i}; }}\n"
        )

    # Generate main.c
    lines = [
        '/* Auto-generated stress test: %d DT_NEEDED encrypted libs */' % n,
        '#include <stdio.h>',
        '',
    ]
    for i in range(1, n + 1):
        lines.append(f'extern int stress_{i:02d}_func(int);')
    lines.append('')
    lines.append('int main(void)')
    lines.append('{')
    lines.append('    int fail = 0;')
    lines.append('    int result;')
    for i in range(1, n + 1):
        lines.append(f'    result = stress_{i:02d}_func(100);')
        lines.append(f'    if (result != {100 + i}) {{ fprintf(stderr, "FAIL: stress_{i:02d}_func(100)=%d (expected {100 + i})\\n", result); fail++; }}')
    lines.append(f'    if (fail == 0) printf("PASS: many_libs ({n} libs, {n} functions)\\n");')
    lines.append(f'    else printf("FAIL: %d/{n} checks failed\\n", fail);')
    lines.append('    return fail;')
    lines.append('}')
    (outdir / 'main.c').write_text('\n'.join(lines) + '\n')

    print(f'[gen_libs] Generated {n} libs + main.c in {outdir}')

if __name__ == '__main__':
    main()
