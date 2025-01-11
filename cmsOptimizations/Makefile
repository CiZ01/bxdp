TARGETS := bcms ubcms cms obcms sobcms rbcms robcms rcms
#cms regular single pkt version
#rcms single pkt random
#ubcms 4 map access batched version
#bcms 1 map access batched
#obcms loop unrolling
#sobcms loop unrolling and split map access
#rbcms 4 random
#robcms 1 random



.PHONY : all clean

all: clean $(TARGETS)

$(TARGETS): 
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf

clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
