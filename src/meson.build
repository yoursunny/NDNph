mbedcrypto = meson.get_compiler('cpp').find_library('mbedcrypto', required: false)
if mbedcrypto.found()
  mbedcrypto_dep = declare_dependency(compile_args: ['-DNDNPH_PORT_CRYPTO_MBEDTLS'], dependencies: [mbedcrypto])
else
  mbedcrypto_dep = declare_dependency()
endif

urandom = not meson.is_cross_build() and run_command('test', '-r', '/dev/urandom').returncode() == 0
if urandom
  urandom_dep = declare_dependency(compile_args: ['-DNDNPH_PORT_RANDOM_URANDOM'])
else
  urandom_dep = declare_dependency()
endif

socket_h = not meson.is_cross_build() and meson.get_compiler('cpp').has_header('sys/socket.h')
if socket_h
  socket_dep = declare_dependency(compile_args: ['-DNDNPH_PORT_TRANSPORT_SOCKET'])
else
  socket_dep = declare_dependency()
endif

lib_dep = declare_dependency(include_directories: ['.'], dependencies: [mbedcrypto_dep, urandom_dep, socket_dep])
