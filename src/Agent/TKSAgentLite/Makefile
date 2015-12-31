################################################################
# Makefile
#
# Copyright 2015 hbwoo
#
#  This file is part of TrustKeystoreAgent

#OPT = -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections

CFLAGS = -I../wolfssl-3.4.6 $(OPT) -DTKSAGENTLITE_EXPORTS
TARGET = built-in.o
SRCS = $(wildcard ../TrustKeystoreAgent/*.c)
OBJS = $(patsubst ../TrustKeystoreAgent/%.c, %.o, $(wildcard ../TrustKeystoreAgent/*.c))

all : compile $(OBJS)
	$(LD) -r $(OBJS) -o $(TARGET)

compile : $(SRCS)
	$(CC) $(CFLAGS) -c $(SRCS)

clean :
	rm -rf *.o $(TARGET)
