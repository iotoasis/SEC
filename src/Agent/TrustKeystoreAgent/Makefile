################################################################
# Makefile
#
# Copyright 2015 hbwoo
#
#  This file is part of TrustKeystoreAgent

#OPT = -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections

CFLAGS = -I../wolfssl-3.4.6 $(OPT) -DTRUSTKEYSTOREAGENT_EXPORTS #-D_DEBUG
TARGET = built-in.o
TARGET_LIB = libTrustKeystoreAgent.a
OBJS = $(patsubst %.c, %.o, $(wildcard *.c))

all : $(OBJS)	
	$(LD) -r $(OBJS) -o $(TARGET)
	$(AR) rv $(TARGET_LIB) $(OBJS)

clean :
	rm -rf *.o $(TARGET)
