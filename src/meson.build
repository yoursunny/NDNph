conf = configuration_data()

boost = dependency('boost', required: false)
conf.set('NDNPH_PORT_QUEUE_BOOSTLF', boost.found())

mbedcrypto = meson.get_compiler('cpp').find_library('mbedcrypto', required: false)
conf.set('NDNPH_PORT_CRYPTO_MBEDTLS', mbedcrypto.found())

have_urandom = not meson.is_cross_build() and run_command('test', '-r', '/dev/urandom').returncode() == 0
conf.set('NDNPH_PORT_RANDOM_URANDOM', have_urandom)

have_socket_h = not meson.is_cross_build() and meson.get_compiler('cpp').has_header('sys/socket.h')
conf.set('NDNPH_PORT_TRANSPORT_SOCKET', have_socket_h)

have_this_thread = meson.get_compiler('cpp').compiles('''
#include <chrono>
#include <thread>
int main()
{
  std::this_thread::sleep_for(std::chrono::milliseconds(1));
}
''')
conf.set('NDNPH_PORT_CHRONO_BUSY_SLEEP', not have_this_thread)

config_h = configure_file(output: 'NDNph-config.h', configuration: conf)
lib_dep = declare_dependency(
  include_directories: include_directories('.'),
  compile_args: ['-include', 'NDNph-config.h'],
  dependencies: [boost, mbedcrypto])

install_subdir('ndnph', install_dir: 'include')
install_headers('NDNph.h', config_h)
