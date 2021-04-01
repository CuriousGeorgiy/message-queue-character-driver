KDIR ?= /lib/modules/$(shell uname -r)/build

FNAME_C := message_queue_character_driver

PWD          := $(shell pwd)
obj-m        += ${FNAME_C}.o
EXTRA_CFLAGS += -DDEBUG


.DEFAULT_GOAL: all
.PHONE: all clean

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
