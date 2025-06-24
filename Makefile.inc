COMPILER=gcc

COMPILERFLAGS=-Wall -pedantic -g -pthread -Wno-pointer-arith  -std=c11 -D_POSIX_C_SOURCE=200112L -fsanitize=address -fsanitize=undefined

CHECK_CFLAGS := $(shell pkg-config --cflags check)
CHECK_LDFLAGS := $(shell pkg-config --libs check)


LDFLAGS=
