project('bitcoin', 'c',
  version : '0.1',
  default_options : ['warning_level=3'])

endianess_template = '@0@_ENDIAN'
endian = endianess_template.format(target_machine.endian()).to_upper()
add_project_arguments('-D' + endian, language: 'c')

version_template = 'v@0@'
version = version_template.format(meson.project_version())
add_project_arguments('-DVERSION=' + version , language: 'c')

subdir('external')
subdir('src')
subdir('test')