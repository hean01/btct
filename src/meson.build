nettle = dependency('nettle', version: '>=3.4',
                    method: 'pkg-config',
                    required: true)

sources = [
  'utils.c',
  'command.c',
  'bip32.c',
  'bip32_command.c',
  'bip39_command.c',
  'bip39.c',
  'sss_command.c',
]

libbtct_static = static_library('btct', sources,
	    link_with: [libbase58_static, sss_static],
	    include_directories: [sss_incdir])

executable('btct', 'btct.c',
           dependencies: [ nettle ],
           link_with: [libbtct_static],
           install: true)
