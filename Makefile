NS=port-hopper-namespace
NS_OUTER_DEV=outer_veth
NS_INNER_DEV=inner_veth
MAP_PATH=/sys/fs/bpf/hopper/map
PROG_PATH=/sys/fs/bpf/hopper/prog

all:
	clang -O2 -Wall -g -target bpf -c src/hopper.bpf.c -o build/hopper.bpf.o
	clang -O2 -Wall -g $(shell pkg-config --libs --cflags libbpf) src/user.c -o build/user

xl: xun all
	sudo mkdir -p $(MAP_PATH) $(PROG_PATH)
	sudo bpftool prog loadall build/hopper.bpf.o $(PROG_PATH) pinmaps $(MAP_PATH)
	@sudo bpftool net attach tcx_ingress pinned $(PROG_PATH)/tc_port_hopper_ingress dev $(NS_OUTER_DEV)
	@sudo bpftool net attach tcx_egress  pinned $(PROG_PATH)/tc_port_hopper_egress   dev $(NS_OUTER_DEV)
	@sudo ip netns exec $(NS) bash -c "mount --bind /var/run/netns/bpf/ /sys/fs/bpf/; make xin;"
	@sudo ./build/user
	@echo -e '\nLoad Success\n'

vm: vm_clean
	sudo ip l a br0 type bridge
	sudo ip l s dev br0 up
	sudo qemu-kvm --enable-kvm -m 1G -hda iso/alpine.img -snapshot -daemonize \
		-device e1000,mac=aa:54:00:00:00:91,netdev=lan,id=lan -netdev tap,id=lan,ifname=tap0,script=no,downscript=no
	sudo qemu-kvm --enable-kvm -m 1G -hda iso/alpine.img -snapshot -daemonize \
		-device e1000,mac=ee:55:00:00:00:91,netdev=lan,id=lan -netdev tap,id=lan,ifname=tap1,script=no,downscript=no
	sudo ip l s dev tap0 master br0
	sudo ip l s dev tap1 master br0
	sudo ip l s dev tap0 up
	sudo ip l s dev tap1 up
	sudo ip a add 192.168.1.1/24 dev br0


xin:
	- @sudo bpftool net detach tcx_ingress dev $(NS_INNER_DEV)
	- @sudo bpftool net detach tcx_egress dev $(NS_INNER_DEV)
	@sudo bpftool net attach tcx_ingress pinned $(PROG_PATH)/tc_port_hopper_ingress dev $(NS_INNER_DEV)
	@sudo bpftool net attach tcx_egress  pinned $(PROG_PATH)/tc_port_hopper_egress   dev $(NS_INNER_DEV)
	@echo -e '\nInternal Load Success\n'

xun:
	- @sudo bpftool net detach tcx_ingress dev $(NS_OUTER_DEV)
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

clean: ns_dwn
	- sudo ip l d br0
	$(RM) build/*.o

.PHONY: all clean