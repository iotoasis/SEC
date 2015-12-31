################################################################
# Makefile
#
# Copyright 2015 hbwoo
#
#  This file is part of TrustKeystoreAgent

#OPT = -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections

CFLAGS = -I../ $(OPT)
TARGET = built-in.o
TARGET_LIB = libwolfssl.a
OBJS = $(patsubst %.c, %.o, $(wildcard *.c))

all : $(OBJS)		
	$(LD) -r $(OBJS) -o $(TARGET)
	$(AR) rv $(TARGET_LIB) $(OBJS)

clean :
	rm -rf *.o $(TARGET) $(TARGET_LIB)