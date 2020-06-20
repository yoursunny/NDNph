project('NDNph', 'cpp',
  default_options: [
    'warning_level=2',
    'cpp_std=c++11',
    'cpp_eh=none',
    'cpp_rtti=false'
  ])
subdir('src')
subdir('tests')

programs_option = get_option('programs')
if not programs_option.disabled()
  if has_all_linux_deps
    subdir('programs')
  elif programs_option.enabled()
    error('programs enabled but is missing dependency')
  endif
endif
