conf = configuration_data()

boost = dependency('boost', required: false)
if boost.found()
  conf.set('NDNPH_PORT_QUEUE_BOOSTLF', '')
endif

conf.set('NDNPH_PORT_FS_LINUX', '')

mbedcrypto = meson.get_compiler('cpp').find_library('mbedcrypto', required: false)
if mbedcrypto.found()
  conf.set('NDNPH_HAVE_MBED', '')
endif

have_urandom = not meson.is_cross_build() and run_command('test', '-r', '/dev/urandom').returncode() == 0
if have_urandom
  conf.set('NDNPH_PORT_RANDOM_URANDOM', '')
endif

have_socket_h = meson.get_compiler('cpp').has_header('sys/socket.h')
if have_socket_h
  conf.set('NDNPH_PORT_TRANSPORT_SOCKET', '')
endif

have_this_thread = meson.get_compiler('cpp').compiles('''
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
  dependencies: [boost, mbedcrypto])

install_subdir('ndnph', install_dir: 'include')
install_headers('NDNph.h', config_h)
