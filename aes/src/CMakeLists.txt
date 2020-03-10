cmake_minimum_required(VERSION 3.9)

string(TIMESTAMP PACKAGE_DATE %Y-%m-%dT%H:%M:%SZ UTC)
add_definitions( -DPACKAGE_NAME="aescrypt" )
add_definitions( -DPACKAGE_VERSION="1.0.0" )
add_definitions( -DPACKAGE_DATE="${PACKAGE_DATE}" )

set( HEADER_FILES
   password.h
   aes.h
   aesrandom.h
   sha256.h
   util.h
   keyfile.h )

set( COMMON_SOURCE_FILES
   aes.c
   aesrandom.c
   sha256.c
   util.c
   keyfile.c
   password.c )

add_executable( aescrypt aescrypt.c ${COMMON_SOURCE_FILES} )
add_executable( aescrypt_keygen aescrypt_keygen.c ${COMMON_SOURCE_FILES} )
