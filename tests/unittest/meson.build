boost = dependency('boost')
gmock = dependency('gmock')
gtest = dependency('gtest', main: true)
assert(mbedcrypto.found(), 'libmbedcrypto is required to build unit tests')
assert(urandom, 'urandom is required to build unit tests')

unittest_exe = executable('unittest',
  unittest_files,
  dependencies: [lib_dep, boost, gmock, gtest],
  include_directories: ['..'],
)
test('unittest', unittest_exe)
