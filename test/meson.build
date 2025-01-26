ncurses = dependency('ncurses', version: '>=6.0',
                    method: 'pkg-config',
                    required: true)

bip32_spec = executable('bip32_spec', 'bip32_spec.c', dependencies: [ ncurses, nettle ], link_with: [libbtct_static])
bip39_spec = executable('bip39_spec', 'bip39_spec.c', dependencies: [ ncurses, nettle ], link_with: [libbtct_static])

test('bip32_spec', bip32_spec)
test('bip39_spec', bip39_spec)
