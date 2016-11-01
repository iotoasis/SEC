################################################################
# Makefile
#
# Copyright 2016 hbwoo
#
#  This file is part of TrustNETCASClient

#OPT = -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections

CFLAGS = -DHAVE_MEMMOVE $(OPT)
TARGET = built-in.o
TARGET_LIB = libexpat.a
OBJS = $(patsubst %.c, %.o, $(wildcard *.c))

all : $(OBJS)
	$(LD) -r $(OBJS) -o $(TARGET)
	$(AR) rv $(TARGET_LIB) $(OBJS)

clean :
	rm -rf *.o $(TARGET) $(TARGET_LIB)
