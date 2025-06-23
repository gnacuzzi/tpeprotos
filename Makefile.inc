COMPILER=gcc

COMPILERFLAGS=-Wall -pedantic -g -pthread -Wno-pointer-arith  -std=c11 

CHECK_CFLAGS := $(shell pkg-config --cflags check)
CHECK_LDFLAGS := $(shell pkg-config --libs check)


LDFLAGS=
