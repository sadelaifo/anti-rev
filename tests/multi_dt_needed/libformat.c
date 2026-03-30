#include <stdio.h>
#include <string.h>

int format_int(char *buf, int buflen, int val) {
    return snprintf(buf, (size_t)buflen, "[%d]", val);
}

int format_len(const char *s) {
    return (int)strlen(s);
}
