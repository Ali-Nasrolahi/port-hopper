NS=port-hopper-namespace
NS_OUTER_DEV=outer_veth
NS_INNER_DEV=inner_veth
MAP_PATH=/sys/fs/bpf/hopper/map
PROG_PATH=/sys/fs/bpf/hopper/prog

all: hopper.bpf.o user

%.o:%.c
	clang -O2 -Wall -g -target bpf -c $^ -o build/$@

user: user.c
	clang -O2 -Wall -g -lbpf $^ -o build/$@

xl: xun all
	sudo mkdir -p $(MAP_PATH) $(PROG_PATH)
	sudo bpftool prog loadall build/hopper.bpf.o $(PROG_PATH) pinmaps $(MAP_PATH)
	@sudo bpftool net attach xdp pinned $(PROG_PATH)/xdp_port_hopper_ingress dev $(NS_OUTER_DEV)
	@sudo bpftool net attach tcx_egress  pinned $(PROG_PATH)/tc_port_hopper_egress   dev $(NS_OUTER_DEV)
	@sudo ip netns exec $(NS) bash -c "mount --bind /var/run/netns/bpf/ /sys/fs/bpf/; make xin;"
	@sudo ./build/user
	@echo -e '\nLoad Success\n'

xin:
	- @sudo bpftool net detach xdp dev $(NS_INNER_DEV)
	- @sudo bpftool net detach tcx_egress dev $(NS_INNER_DEV)
	@sudo bpftool net attach xdp pinned $(PROG_PATH)/xdp_port_hopper_ingress dev $(NS_INNER_DEV)
	@sudo bpftool net attach tcx_egress  pinned $(PROG_PATH)/tc_port_hopper_egress   dev $(NS_INNER_DEV)
	@echo -e '\nInternal Load Success\n'

xun:
	- @sudo bpftool net detach xdp dev $(NS_OUTER_DEV)
	- @sudo bpftool net detach tcx_egress dev $(NS_OUTER_DEV)
	- @sudo rm -r /sys/fs/bpf/hopper/

ns_up: ns_dwn
	@sudo ip netns add $(NS)
	@sudo ip l a dev $(NS_OUTER_DEV) type veth peer $(NS_INNER_DEV) netns $(NS)
	@sudo ip l s $(NS_OUTER_DEV) up
	@sudo ip a a 192.168.1.1/24 dev $(NS_OUTER_DEV)
	@sudo ip netns exec $(NS) ip l s $(NS_INNER_DEV) up
	@sudo ip netns exec $(NS) ip a a 192.168.1.2/24 dev $(NS_INNER_DEV)
	@sudo ip netns exec $(NS) tc qdisc add dev $(NS_INNER_DEV) clsact
	@sudo tc qdisc add dev $(NS_OUTER_DEV) clsact
	@sudo mkdir -p /var/run/netns/bpf
	@sudo mount --bind /sys/fs/bpf/ /var/run/netns/bpf
	@echo 'Namespace UP!'

ns_dwn: xun
	- @sudo umount /var/run/netns/bpf
	- @sudo ip netns d $(NS)

ns_en:
	sudo ip netns exec $(NS) \
		bash -c "mount --bind /var/run/netns/bpf/ /sys/fs/bpf/; \
		make xin; \
		env PS1='# ' bash"

clean:
	$(RM) build/*.o

.PHONY: all clean