project(yara-har)
cmake_minimum_required(VERSION 3.12)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads)

include(ExternalProject)

ExternalProject_Add(yara
	URL https://github.com/VirusTotal/yara/archive/v3.8.1.tar.gz
	URL_HASH SHA512=32acb7b7336eebe2fe2c10ba6e8b23fea4e91148c289d15b53119bbed3dfe27508fbd90aef5c036a5b6a7e31e0f73ec8885e30093c598f9bc04bd9d64ac0ac7e
	PATCH_COMMAND patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/0001-Add-initial-har_entry-module.patch
	CONFIGURE_COMMAND ./bootstrap.sh
	          COMMAND ./configure --with-pic --enable-debug
	CMAKE_GENERATOR make
	BUILD_IN_SOURCE 1
	BUILD_BYPRODUCTS
		<SOURCE_DIR>/libyara/.libs/libyara.a
		<SOURCE_DIR>/libyara/.libs/libyara.so
		<SOURCE_DIR>/libyara/.libs/libyara.so.3
		<SOURCE_DIR>/libyara/.libs/libyara.so.3.8.1
	INSTALL_COMMAND ""
)

add_library(libyara STATIC IMPORTED GLOBAL)
set_target_properties(libyara
	PROPERTIES
		IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/yara-prefix/src/yara/libyara/.libs/libyara.a
)
add_dependencies(libyara yara)

include_directories(
	${CMAKE_CURRENT_BINARY_DIR}/yara-prefix/src/yara/libyara/include
	${CMAKE_CURRENT_SOURCE_DIR}
)
add_library(yara-har-lib SHARED
	libyara-har.h
	libyara-har.c
	mbedtls/config.h
	mbedtls/base64.h
	mbedtls/base64.c
)
set_target_properties(yara-har-lib
	PROPERTIES
		OUTPUT_NAME yara-har
)
target_link_libraries(yara-har-lib libyara jansson OpenSSL::Crypto m ${CMAKE_THREAD_LIBS_INIT})

add_executable(yara-har-bin yara-har.c)
set_target_properties(yara-har-bin
	PROPERTIES
		OUTPUT_NAME yara-har
)
target_link_libraries(yara-har-bin yara-har-lib)

enable_testing()

add_test(
	NAME firefox.google.favicon
	COMMAND
		${CMAKE_CURRENT_BINARY_DIR}/yara-har
		${CMAKE_CURRENT_SOURCE_DIR}/rules/www.google.com.yara
		${CMAKE_CURRENT_SOURCE_DIR}/examples/firefox_www.google.com.har
		favicon
)

add_test(
	NAME chromium.google.favicon
	COMMAND
		${CMAKE_CURRENT_BINARY_DIR}/yara-har
		${CMAKE_CURRENT_SOURCE_DIR}/rules/www.google.com.yara
		${CMAKE_CURRENT_SOURCE_DIR}/examples/chromium_www.google.com.har
		favicon
)
