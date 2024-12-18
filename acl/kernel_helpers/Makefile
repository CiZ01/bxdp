obj-m += ebpf_avx.o
GCC_VERSION ?= 13
CLANG_VERSION ?= 18.1.3
CC_SIMD_OPTS ?= -mavx2 -mbmi -mavx512f -march=native

ifeq ($(LLVM),1)
ccflags-y += -I/usr/lib/llvm-$(shell echo $(CLANG_VERSION) | cut -d. -f1)/lib/clang/$(CLANG_VERSION)/include $(CC_SIMD_OPTS)
else
ccflags-y += -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include $(CC_SIMD_OPTS)
endif

all:
	@echo "Building ebpf_avx..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) -I ../common.h modules

clean:
	@echo "Cleaning ebpf_avx..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod ebpf_avx.ko

unload:
	sudo rmmod ebpf_avx.ko

reload:
	sudo rmmod ebpf_avx.ko
	sudo insmod ebpf_avx.ko