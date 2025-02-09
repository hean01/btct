
libbase58_static = static_library('libbase58', 'libbase58/base58.c')

sss_incdir = include_directories(['sss/'])
sss_static = static_library('sss', ['sss/sss.c', 'sss/randombytes.c', 'sss/tweetnacl.c', 'sss/hazmat.c'],
                            include_directories: sss_incdir)

secp256k1_incdir = include_directories(['secp256k1/include'])
secp256k1_static = static_library('secp256k1', [
  'secp256k1/src/secp256k1.c',
  'secp256k1/src/precomputed_ecmult.c',
  'secp256k1/src/precomputed_ecmult_gen.c',
],
                                  c_args: ['-DSECP256K1_BUILD', '-DSECP256K1_STATIC'],
                                  include_directories: secp256k1_incdir)
