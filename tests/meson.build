subproject('gtest')
gmock = dependency('gmock')
gtest = dependency('gtest_main')

subdir('unit')
unittest_exe = executable('unittest',
  unittest_files,
  dependencies: [lib_dep, gmock, gtest],
  include_directories: ['.'],
)
test('unittest', unittest_exe)
