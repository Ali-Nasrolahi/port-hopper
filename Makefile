NS=port-hopper-namespace
NS_OUTER_DEV=outer_veth
NS_INNER_DEV=inner_veth
ATTACH_CMD=legacy_attach
DETACH_CMD=legacy_detach
ATTACH_CMD=attach
DETACH_CMD=detach
DEV=dum0

all:
	clang -O2 -Wall -g -target bpf -c src/bpf/hopper.bpf.c -o build/hopper.bpf.o
	go generate -C src/
	go build -C src/ -o ../build/hopper

xl: xun all
	@sudo build/hopper load
	@sudo build/hopper $(ATTACH_CMD) -device $(NS_OUTER_DEV)
	@sudo build/hopper config -device $(NS_OUTER_DEV) -inbound 8080 -min 9000 -max 9999
	@sudo ip netns exec $(NS) bash -c "mount --bind /var/run/netns/bpf/ /sys/fs/bpf/; make xin;"
	@echo -e '\nLoad Success\n'

vm_rhel:
	qemu-kvm --enable-kvm -cpu host -smp 2 -m 2G -hda iso/rhel9.img -nic user -daemonize

vm_alpine: vm_clean
	sudo ip l a br0 type bridge
	sudo ip l s dev br0 up
	sudo qemu-kvm --enable-kvm -cpu host -m 1G -hda iso/alpine.img -snapshot -daemonize \
		-device e1000,mac=aa:54:00:00:00:91,netdev=lan,id=lan -netdev tap,id=lan,ifname=tap0,script=no,downscript=no
	sudo qemu-kvm --enable-kvm -cpu host -m 1G -hda iso/alpine.img -snapshot -daemonize \
		-device e1000,mac=ee:55:00:00:00:91,netdev=lan,id=lan -netdev tap,id=lan,ifname=tap1,script=no,downscript=no
	sudo ip l s dev tap0 master br0
	sudo ip l s dev tap1 master br0
	sudo ip l s dev tap0 up
	sudo ip l s dev tap1 up
	sudo ip a add 192.168.1.1/24 dev br0

xin:
	@sudo ./build/hopper $(DETACH_CMD) -device $(NS_INNER_DEV)
	@sudo ./build/hopper $(ATTACH_CMD) -device $(NS_INNER_DEV)
	@sudo ./build/hopper config -device $(NS_INNER_DEV) -inbound 8080 -min 9000 -max 9999

xun:
	- @sudo ./build/hopper $(DETACH_CMD) -device $(NS_OUTER_DEV)
	- @sudo rm -r /sys/fs/bpf/hopper/

ns_up: ns_dwn
	@sudo ip netns add $(NS)
	@sudo ip l a dev $(NS_OUTER_DEV) type veth peer $(NS_INNER_DEV) netns $(NS)
	@sudo ip l s $(NS_OUTER_DEV) up
	@sudo ip a a 192.168.1.1/24 dev $(NS_OUTER_DEV)
	@sudo ip netns exec $(NS) ip l s $(NS_INNER_DEV) up
	@sudo ip netns exec $(NS) ip a a 192.168.1.2/24 dev $(NS_INNER_DEV)
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
