ncurses = dependency('ncurses', version: '>=6.2',
                    method: 'pkg-config',
                    required: true)

bip39_spec = executable('bip39_spec', 'bip39_spec.c', dependencies: [ ncurses, nettle ], link_with: [libbtct_static])

test('bip39_spec', bip39_spec)
