TARGETS := bcms cms tbcms tcms obcms sobcms abcms aobcms ubcms
ALGN := 64

.PHONY : all clean

all: clean $(TARGETS)

$(TARGETS): 
	@echo "algn value: $(ALGN)"
	clang -g -O3 --target=bpf -c $@.bpf.c -o $@.bpf.o -DALGN=$(ALGN)
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf

clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)

