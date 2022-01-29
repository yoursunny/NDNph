#ifndef NDNPH_CORE_COMMON_HPP
#define NDNPH_CORE_COMMON_HPP

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <sys/types.h>

#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>

#ifdef NDEBUG
#define NDNPH_ASSERT(x) (void)(x)
#else
#define NDNPH_ASSERT(x) assert(x)
#endif

/** @brief SHA256 digest length. */
#define NDNPH_SHA256_LEN 32

#ifndef NDNPH_PITTOKEN_MAX
/**
 * @brief Maximum length of PIT token.
 *
 * You may override this setting by declaring the macro before including NDNph.
 * This must be between 4 (NDNph requirement) and 32 (protocol limit).
 * Setting a lower limit reduces memory usage, but is non-interoperable with downstream
 * nodes that require a longer PIT token.
 */
#define NDNPH_PITTOKEN_MAX 10
#endif

#endif // NDNPH_CORE_COMMON_HPP
