find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
pkg_search_module(GCRYPT REQUIRED libgcrypt)

file(GLOB LIB_SOURCES "*.c")
add_library(libgcrypt_debug STATIC ${LIB_SOURCES})
target_include_directories(libgcrypt_debug PUBLIC ${GLIB_INCLUDE_DIRS})
target_link_libraries(libgcrypt_debug PUBLIC ${GLIB_LIBRARIES})
target_compile_options(libgcrypt_debug PUBLIC ${GLIB_CFLAGS_OTHER} "-O0")

target_include_directories(libgcrypt_debug PUBLIC ${GCRYPT_INCLUDE_DIRS})
target_link_libraries(libgcrypt_debug PUBLIC ${GCRYPT_LIBRARIES})
target_compile_options(libgcrypt_debug PUBLIC ${GCRYPT_CFLAGS_OTHER} "-O0")