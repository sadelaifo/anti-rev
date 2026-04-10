/*
 * Library with a C++ global static initializer that calls
 * readlink("/proc/self/exe") — reproduces the case where a DT_NEEDED
 * library resolves process identity before exe_shim's constructor runs.
 */
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <cstdio>
#include <string>

static std::string GetProcessName() noexcept
{
    const int buffSize = 1024;
    char buff[buffSize] = {0};
    ssize_t ret = readlink("/proc/self/exe", buff, buffSize - 1);
    if (ret > 0)
        buff[ret] = '\0';
    return basename(buff);
}

/* Global static — initialized before main(), during .init_array */
static const std::string PROCESS_NAME = GetProcessName();

extern "C" const char *get_ctor_process_name(void)
{
    return PROCESS_NAME.c_str();
}

extern "C" const char *get_runtime_process_name(void)
{
    static std::string name = GetProcessName();
    return name.c_str();
}
