#pragma once

// The authoritative build force-includes this header in every C++ compile.
// That turns the effective compiler mode into a per-translation-unit contract:
// a library or source-specific flag cannot silently switch exceptions off.
#if !defined(__cplusplus)
#error "XTINCT exception guard must only be force-included for C++"
#endif

#if !defined(__cpp_exceptions)
#error "XTINCT requires effective C++ exception support in every project translation unit"
#endif

static_assert(__cpp_exceptions >= 199711L,
              "XTINCT requires the standard C++ exception feature macro");
