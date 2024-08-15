cmake_minimum_required(VERSION 3.6.0)
add_library(x7 SHARED aes_helper.c blake.c bmw.c  echo.c groestl.c hashblock.cpp keccak.c luffa.c skein.c)
include_directories(.)
