#ifndef NDNPH_TEST_COMMON_HPP
#define NDNPH_TEST_COMMON_HPP

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace T = testing;

#ifndef NDNPH_HAS_BOOST_CONCEPT
#define NDNPH_HAS_BOOST_CONCEPT 1
#endif
#if NDNPH_HAS_BOOST_CONCEPT
#include <boost/concept_check.hpp>
#endif

#endif // NDNPH_TEST_COMMON_HPP
