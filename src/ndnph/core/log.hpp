#ifndef NDNPH_CORE_LOG_HPP
#define NDNPH_CORE_LOG_HPP

#include "common.hpp"
#ifdef ARDUINO
#include "../port/clock/port.hpp"
#else
#include "../port/unixtime/port.hpp"
#endif

#ifndef NDNPH_LOG_PRINTF
#ifdef ARDUINO
#define NDNPH_LOG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
#ifndef NDNPH_LOG_FILE
#define NDNPH_LOG_FILE stderr
#endif
#define NDNPH_LOG_PRINTF(...) fprintf((NDNPH_LOG_FILE), ##__VA_ARGS__)
#endif
#endif // NDNPH_LOG_PRINTF

#ifndef NDNPH_LOG_NOWVAR
#ifdef ARDUINO
#define NDNPH_LOG_NOWVAR millis()
#else
#define NDNPH_LOG_NOWVAR (ndnph::port::UnixTime::now() / 1000)
#endif
#endif // NDNPH_LOG_NOWVAR

#ifndef NDNPH_LOG_NOWFMT
#ifdef ARDUINO
#define NDNPH_LOG_NOWFMT "%lu"
#else
#define NDNPH_LOG_NOWFMT "%" PRIu64
#endif
#endif // NDNPH_LOG_NOWFMT

/**
 * @brief Log a message without "\n".
 * @param category message category. It may contain format specifiers for variables after @p fmt .
 * @param fmt format string.
 */
#define NDNPH_LOG_MSG(category, fmt, ...)                                                          \
  NDNPH_LOG_PRINTF(NDNPH_LOG_NOWFMT " [" category "] " fmt, NDNPH_LOG_NOWVAR, ##__VA_ARGS__)

/**
 * @brief Log a message with "\n".
 * @sa NDNPH_LOG_MSG
 */
#define NDNPH_LOG_LINE(category, fmt, ...) NDNPH_LOG_MSG(category, fmt "\n", ##__VA_ARGS__)

#endif // NDNPH_CORE_LOG_HPP
