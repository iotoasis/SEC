################################################################
# Makefile
#
# Copyright 2016 hbwoo
#
#  This file is part of TrustNETCASClient

#OPT = -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections

CFLAGS = -I../../ -DNO_MD4 -DWOLFSSL_MISC_INCLUDED $(OPT)

TARGET = built-in.o
TARGET_LIB = libwolfcrypt.a
OBJS = $(patsubst %.c, %.o, $(wildcard *.c))

all : $(OBJS)	
	$(LD) -r $(OBJS) -o $(TARGET)
	$(AR) rv $(TARGET_LIB) $(OBJS)

clean :
	rm -rf *.o $(TARGET) $(TARGET_LIB)