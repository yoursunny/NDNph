project('NDNph', 'cpp',
  default_options: [
    'warning_level=2',
    'cpp_std=c++11',
    'cpp_eh=none',
    'cpp_rtti=false'
  ],
  meson_version: '>=1.0.0'
)

subdir('src')

if get_option('unittest').require(has_all_linux_deps).allowed()
  subdir('tests')
endif

if get_option('programs').require(has_all_linux_deps).allowed()
  subdir('programs')
endif
