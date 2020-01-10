mbedcrypto = meson.get_compiler('cpp').find_library('mbedcrypto', required: false)
if mbedcrypto.found()
  mbedcrypto_dep = declare_dependency(compile_args: ['-DNDNPH_PORT_MBEDTLS=1'], dependencies: [mbedcrypto])
else
  mbedcrypto_dep = declare_dependency(compile_args: ['-DNDNPH_PORT_MBEDTLS=0'])
endif

if meson.is_cross_build()
  urandom = false
else
  urandom = run_command('test', '-r', '/dev/urandom').returncode() == 0
endif
urandom_dep = declare_dependency(compile_args: ['-DNDNPH_PORT_URANDOM=@0@'.format(0 + urandom)])

lib_dep = declare_dependency(include_directories: ['.'], dependencies: [mbedcrypto_dep, urandom_dep])
