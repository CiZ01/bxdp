TARGETS := bnitro1 bnitro2 obnitro1 obnitro2


.PHONY : all clean

all: clean $(TARGETS)

$(TARGETS): 
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf -lgsl -lgslcblas -lm

clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
