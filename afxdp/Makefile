TARGETS := afxdp

.PHONY : all clean

all: clean $(TARGETS)

$(TARGETS): 
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o -DALGN=$(ALGN)
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf -lxdp

clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
