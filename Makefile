obj-m += af_inet6_ext.o

# ordinary compiles:
KERN_BUILD := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KERN_BUILD) M=$(PWD) modules

clean:
	make -C $(KERN_BUILD) M=$(PWD) clean