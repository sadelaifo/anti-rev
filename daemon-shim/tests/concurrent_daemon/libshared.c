#include <unistd.h>

int shared_getpid(void) { return (int)getpid(); }
int shared_add(int a, int b) { return a + b; }
