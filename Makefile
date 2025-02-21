SUBDIRS := acl \
           bsoftware/cms \
           bsoftware/conntrack \
           bsoftware/nat \
           bsoftware/nitroSketch \
           bsoftware/router \
           cms \
           cmsOptimizations \
           conntrack \
           dpdk \
           drop \
           loadbalancer \
           map \
           nat \
           nitroSketch \
           pass \
           router \
           sampler \
           tx
           #xxhash

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	@$(MAKE) -C $@

clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done
