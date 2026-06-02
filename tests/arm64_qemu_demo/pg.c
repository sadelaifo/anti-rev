/* Program-binary ELF loaded by ANTI_LoadProcess.  Encrypted; the shim
 * fetches its decrypted memfd from the daemon (OP_GET_LIB) and rewrites
 * ltrBin so the real ANTI_LoadProcess never sees the on-disk ciphertext. */
#include <stdio.h>
int main(void)
{
    printf("[pg.elf] loaded via ANTI_LoadProcess, running\n");
    return 55;
}
