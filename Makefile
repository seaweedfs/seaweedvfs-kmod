# SPDX-License-Identifier: GPL-2.0
# Out-of-tree kbuild for the seaweedvfs kernel module.
#
# Build against the running kernel's headers by default:
#   make            # build seaweedvfs.ko
#   make clean
#   make KDIR=/lib/modules/<ver>/build   # build against a specific kernel

obj-m += seaweedvfs.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
