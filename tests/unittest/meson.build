gmock = dependency('gmock')
gtest = dependency('gtest', main: true)
assert(boost.found(), 'Boost headers are required to build unit tests')
assert(mbedcrypto.found(), 'libmbedcrypto is required to build unit tests')
assert(have_urandom, '/dev/urandom is required to build unit tests')
assert(have_socket_h, 'sys/socket.h is required to build unit tests')

unittest_exe = executable('unittest',
  unittest_files,
  dependencies: [lib_dep, gmock, gtest],
  include_directories: ['..'],
)
test('unittest', unittest_exe)
