cmake = import('cmake')
fs = import('fs')
cpp = meson.get_compiler('cpp')

conf = configuration_data()

boost = dependency('boost', required: false)
if boost.found()
  conf.set('NDNPH_PORT_QUEUE_BOOSTLF', '')
endif

conf.set('NDNPH_PORT_FS_LINUX', '')

mbedcrypto = cpp.find_library('mbedcrypto', has_headers: ['mbedtls/ecdh.h'], required: false)
if mbedcrypto.found()
  conf.set('NDNPH_HAVE_MBED', '')
endif

have_urandom = not meson.is_cross_build() and fs.exists('/dev/urandom')
if have_urandom
  conf.set('NDNPH_PORT_RANDOM_URANDOM', '')
endif

have_socket_h = cpp.has_header('sys/socket.h')
if have_socket_h
  conf.set('NDNPH_PORT_TRANSPORT_SOCKET', '')
endif

libmemif = cpp.find_library('memif', has_headers: ['libmemif.h'], required: false)
if libmemif.found()
  conf.set('NDNPH_PORT_TRANSPORT_MEMIF', '')
endif

have_this_thread = cpp.compiles('''
#include <chrono>
#include <thread>
int main()
{
  std::this_thread::sleep_for(std::chrono::milliseconds(1));
}
''')
if not have_this_thread
  conf.set('NDNPH_PORT_CHRONO_BUSY_SLEEP', '')
endif

has_all_linux_deps = boost.found() and mbedcrypto.found() and have_urandom and have_socket_h

config_h = configure_file(output: 'NDNph-config.h', configuration: conf)
lib_dep = declare_dependency(
  include_directories: include_directories('.'),
  compile_args: ['-include', 'NDNph-config.h'],
  dependencies: [boost, mbedcrypto, libmemif])

install_subdir('ndnph', install_dir: 'include')
install_headers('NDNph.h', config_h)
