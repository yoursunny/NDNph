mbedcrypto = meson.get_compiler('cpp').find_library('mbedcrypto', required: false)
if mbedcrypto.found()
  mbedcrypto_dep = declare_dependency(compile_args: ['-DNDNPH_PORT_MBEDTLS=1'], dependencies: [mbedcrypto])
else
  mbedcrypto_dep = declare_dependency(compile_args: ['-DNDNPH_PORT_MBEDTLS=0'])
endif

lib_dep = declare_dependency(include_directories: ['.'], dependencies: [mbedcrypto_dep])
