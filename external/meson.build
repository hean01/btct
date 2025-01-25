
libbase58_static = static_library('libbase58', 'libbase58/base58.c')

sss_incdir = include_directories(['sss/'])
sss_static = static_library('sss', ['sss/sss.c', 'sss/randombytes.c', 'sss/tweetnacl.c', 'sss/hazmat.c'],
                            include_directories: sss_incdir)
