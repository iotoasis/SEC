################################################################
# Makefile
#
# Copyright 2016 hbwoo
#
#  This file is part of TrustNETCASClient

#OPT = -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections

CFLAGS = -I../wolfssl-3.9.8 $(OPT) -DTRUSTNETCASCLIENT_EXPORTS
TARGET = built-in.o
TARGET_LIB = libTrustNETCASClient.a
OBJS = $(patsubst %.c, %.o, $(wildcard *.c))

all : $(OBJS)	
	$(LD) -r $(OBJS) -o $(TARGET)
	$(AR) rv $(TARGET_LIB) $(OBJS)

clean :
	rm -rf *.o $(TARGET)
