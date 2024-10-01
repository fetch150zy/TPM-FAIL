obj-m += tpmttlcrb.o
obj-m += tpmttltis.o

KBUILD_CFLAGS += -w -msse4 -mpreferred-stack-boundary=4 -O2

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
