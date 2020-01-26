boost = dependency('boost', required: false)
if boost.found()
  add_project_arguments('-DNDNPH_PORT_QUEUE_BOOSTLF', language: 'cpp')
endif

mbedcrypto = meson.get_compiler('cpp').find_library('mbedcrypto', required: false)
if mbedcrypto.found()
  add_project_arguments('-DNDNPH_PORT_CRYPTO_MBEDTLS', language: 'cpp')
endif

have_urandom = not meson.is_cross_build() and run_command('test', '-r', '/dev/urandom').returncode() == 0
if have_urandom
  add_project_arguments('-DNDNPH_PORT_RANDOM_URANDOM', language: 'cpp')
endif

have_socket_h = not meson.is_cross_build() and meson.get_compiler('cpp').has_header('sys/socket.h')
if have_socket_h
  add_project_arguments('-DNDNPH_PORT_TRANSPORT_SOCKET', language: 'cpp')
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
  add_project_arguments('-DNDNPH_PORT_CHRONO_BUSY_SLEEP', language: 'cpp')
endif

lib_dep = declare_dependency(include_directories: ['.'], dependencies: [boost, mbedcrypto])
