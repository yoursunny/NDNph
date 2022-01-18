if has_all_linux_deps
  subproject('gtest')
  gmock = dependency('gmock')
  gtest = dependency('gtest_main')

  unittest_exe = executable('unittest',
    unittest_files,
    dependencies: [lib_dep, gmock, gtest],
    include_directories: ['..'],
  )
  test('unittest', unittest_exe)
elif unittest_option.enabled()
  error('unittest enabled but is missing dependency')
endif
