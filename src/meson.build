nettle = dependency('nettle', version: '>=3.4',
                    method: 'pkg-config',
                    required: true)

sources = [
  'command.c',
  'bip39_command.c',
  'bip39.c',
  'btct.c',
]

executable('btct', sources,
           dependencies: [ nettle ],
           install: true)
