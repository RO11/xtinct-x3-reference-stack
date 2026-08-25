#include <stddef.h>

// The warmed Arduino ESP32-C3 libraries were built with C++ exceptions enabled
// but with a zero-byte libsupc++ emergency arena.  Keep the library's public
// hook while supplying the READY27 value directly from the application.  Both
// symbols live in the same upstream cxx_init.cpp archive member, so defining
// both here prevents that zero-pool member from being selected by the linker.
extern "C" size_t __cxx_eh_arena_size_get(void)
{
    return 1024U;
}

extern "C" void __cxx_init_dummy(void)
{
}
