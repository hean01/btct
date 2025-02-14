nettle = dependency('nettle', version: '>=3.4',
                    method: 'pkg-config',
                    required: true)

gmp = dependency('gmp', version: '>=6.2.0',
                 method: 'pkg-config',
                 required: true)

library_sources = [
  'utils.c',
  'bip32.c',
  'bip39.c',
  'bip44.c',
  'bip85.c',
]

libbtct_static = static_library('btct', library_sources,
                                dependencies: [ gmp ],
	                        link_with: [libbase58_static, secp256k1_static],
	                        include_directories: [sss_incdir])

clitool_sources = [
  'command.c',
  'store.c',
  'store_command.c',
  'bip32_command.c',
  'bip39_command.c',
  'bip44_command.c',
  'bip85_command.c',
  'sss_command.c',
  'btct.c'
]
executable('btct', clitool_sources,
           dependencies: [ gmp, nettle ],
           link_with: [libbtct_static, sss_static],
           include_directories: [sss_incdir],
           install: true)
