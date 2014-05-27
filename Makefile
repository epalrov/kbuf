KMOD := kbuffer
obj-m += $(KMOD).o
$(KMOD)-objs := kbuf.o kfifo.o

KDIR := /lib/modules/$(shell uname -r)/build
DEST := /lib/modules/$(shell uname -r)/kernel/drivers/misc
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
install:
	su -c "cp -v $(KMOD).ko $(DEST) && /sbin/depmod -a"
