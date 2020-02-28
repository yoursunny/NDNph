gmock = dependency('gmock', required: false)
gtest = dependency('gtest', main: true, required: false)
if gmock.found() and gtest.found() and boost.found() and mbedcrypto.found() and have_urandom and have_socket_h
  unittest_exe = executable('unittest',
    unittest_files,
    dependencies: [lib_dep, gmock, gtest],
    include_directories: ['..'],
  )
  test('unittest', unittest_exe)
elif unittest_option.enabled()
  error('unittest enabled but is missing dependency')
endif
