#!/usr/bin/sh

ARGON2PATH=/usr/include/argon2
CC=cc
FLAGS=-Wall
LIBS=-L$ARGON2PATH/src

$CC main.c $ARGON2PATH/libargon2.a $LIBS -o main

