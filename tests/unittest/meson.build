gmock = dependency('gmock', required: true)
gtest = dependency('gtest_main', required: true)

if meson.get_compiler('cpp').has_header('boost/concept_check.hpp')
  boost_concept = declare_dependency(compile_args: '-DNDNPH_HAS_BOOST_CONCEPT=1')
else
  boost_concept = declare_dependency(compile_args: '-DNDNPH_HAS_BOOST_CONCEPT=0')
endif

unittest_exe = executable('unittest',
  unittest_files,
  dependencies: [libdep, gmock, gtest, boost_concept],
)
test('unittest', unittest_exe)
