subproject('gtest')
gmock = dependency('gmock')
gtest = dependency('gtest_main')

subdir('unit')
unittest_exe = executable('unittest',
  unittest_files,
  dependencies: [ndnph_dep, gmock, gtest],
  include_directories: ['.'],
  cpp_args: '-D_GLIBCXX_DEBUG=1',
)
test('unittest', unittest_exe)
