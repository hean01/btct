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
  'btct.c',
]

executable('btct', sources,
           dependencies: [ nettle ],
           link_with: libbase58_static,
           install: true)
