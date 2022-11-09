cmake_minimum_required(VERSION 3.18.1)
project("dashj-bls")
message(STATUS "abi = ${ANDROID_ABI}; ${ANDROID_SYSROOT}")
message(STATUS "binary dir = ${CMAKE_BINARY_DIR}")
set(BUILD_BLS_PYTHON_BINDINGS "0" CACHE STRING "")
set (CMAKE_CXX_FLAGS   "-llog")

set(OPSYS "DROID" CACHE STRING "")
set(CATCH_CONFIG_ANDROID_LOGWRITE "0" CACHE STRING "")

if (${ANDROID_ABI} STREQUAL "x86_64")
	include_directories(${ANDROID_SYSROOT}/usr/include/x86_64-linux-android)
elseif (${ANDROID_ABI} STREQUAL "x86")
	include_directories(${ANDROID_SYSROOT}/usr/include/i686-linux-android)
elseif (${ANDROID_ABI} STREQUAL "arm64-v8a")
	include_directories(${ANDROID_SYSROOT}/usr/include/aarch64-linux-android)
elseif (${ANDROID_ABI} STREQUAL "armeabi-v7a")
	include_directories(${ANDROID_SYSROOT}/usr/include/arm-linux-androideabi)
endif()

# Find Java
# We are only interested in finding jni.h: we do not care about extended JVM
# functionality or the AWT library.
set(JAVA_AWT_LIBRARY NotNeeded)
set(JAVA_JVM_LIBRARY NotNeeded)
set(JAVA_INCLUDE_PATH2 NotNeeded)
set(JAVA_AWT_INCLUDE_PATH NotNeeded)
find_package(JNI REQUIRED)
if (JNI_FOUND)
    message (STATUS "JNI_INCLUDE_DIRS=${JNI_INCLUDE_DIRS}")
    message (STATUS "JNI_LIBRARIES=${JNI_LIBRARIES}")
endif()

include_directories(${JNI_INCLUDE_DIRS}
					${CMAKE_SOURCE_DIR}
					${CMAKE_SOURCE_DIR}/dashj-bls/bls/src/main/cpp
)

find_library(ANDROID_LOG_LIB log)
if (${ANDROID_LOG_LIB})
	target_link_libraries(dashjbls ${ANDROID_LOG_LIB})
else()
	message(STATUS "log lib not found")
endif()
add_library(pthread SHARED pthread.c)

add_subdirectory(dashj-bls/bls)
