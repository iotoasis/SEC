################################################################
# Makefile
#
# Copyright 2016 hbwoo
#
#  This file is part of TrustNETCASClient

TARGET = built-in.o
OBJS = $(patsubst %.c, %.o, $(wildcard *.c))
CFLAGS = $(OPT) $(TEST_OPT)

all : $(OBJS)	
	$(LD) -r $(OBJS) -o $(TARGET)

clean :
	rm -rf *.o $(TARGET)
