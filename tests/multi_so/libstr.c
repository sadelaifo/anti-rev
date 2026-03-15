/* Protected string library */
#include "libstr.h"
#include <string.h>

int str_len(const char *s) { return (int)strlen(s); }
int str_eq(const char *a, const char *b) { return strcmp(a, b) == 0; }
