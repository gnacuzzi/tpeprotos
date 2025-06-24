COMPILER=gcc

COMPILERFLAGS=-Wall -pedantic -g -pthread -Wno-pointer-arith  -std=c11  -fsanitize=address -fsanitize=undefined

CHECK_CFLAGS := $(shell pkg-config --cflags check)
CHECK_LDFLAGS := $(shell pkg-config --libs check)


LDFLAGS=
