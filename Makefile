LINUX_BUILD_DIR ?= /lib/modules/$(shell uname -r)/build

obj-m += syscall-hook.o
syscall-hook-objs += syms.o main.o

all:
	$(MAKE) -C $(LINUX_BUILD_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(LINUX_BUILD_DIR) M=$(PWD) clean
