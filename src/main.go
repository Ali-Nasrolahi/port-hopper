package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -verbose -type event -target bpfel hopper bpf/hopper.bpf.c
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

const (
	IF_NAMESIZE  = 16
	HOP_BPF_DIR  = "/sys/fs/bpf/hopper/"
	MAP_DIR      = (HOP_BPF_DIR + "map/")
	MAP_CONF     = (MAP_DIR + "config")
	MAP_LOG      = (MAP_DIR + "logs")
	PROG_DIR     = (HOP_BPF_DIR + "prog/")
	LINK_DIR     = (HOP_BPF_DIR + "link/")
	PROG_EGRESS  = (PROG_DIR + "egress")
	PROG_INGRESS = (PROG_DIR + "ingress")
)

type hopper_opt struct {
	P      uint16
	Min    uint16
	Max    uint16
	Device [IF_NAMESIZE]byte
}

func main() {
	if len(os.Args) < 2 {
		help()
	}

	switch os.Args[1] {
	case "config":
		config()
	case "dump":
		dump()
	case "load":
		load()
	case "unload":
		unload()
	case "attach":
		attach()
	case "detach":
		detach()
	case "legacy_attach":
		tc_attach()
	case "legacy_detach":
		tc_detach()
	case "tail":
		tail()
	default:
		help()
	}
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}

func help() {
	fmt.Fprintln(os.Stderr, "Usage: hopper <command> [options]")
	fmt.Fprintln(
		os.Stderr,
		"Commands: load, unload, config, dump, attach, detach, legacy_attach, legacy_detach, tail",
	)
	fmt.Fprintln(os.Stderr, "  load")
	fmt.Fprintln(os.Stderr, "  unload")
	fmt.Fprintln(os.Stderr, "  attach --device <interface>")
	fmt.Fprintln(os.Stderr, "  detach --device <interface>")
	fmt.Fprintln(
		os.Stderr,
		"  config --device <interface> --inbound N --min N --max N [--map PATH]",
	)
	fmt.Fprintln(os.Stderr, "  legacy_attach --device <interface>")
	fmt.Fprintln(
		os.Stderr,
		"  legacy_detach --device <interface> \tAttention: Not implemented by Netlink yet. For now runs 'tc filter delete ...' command",
	)
	fmt.Fprintln(os.Stderr, "  dump [--map PATH]")
	fmt.Fprintln(os.Stderr, "  tail [--log-map PATH]")
	os.Exit(1)
}

func (opt *hopper_opt) update(map_path, device string) error {
	if len(device) > IF_NAMESIZE {
		return fmt.Errorf("interface name too long: %s", device)
	}

	if _, err := os.Stat(map_path); os.IsNotExist(err) {
		return fmt.Errorf("map path does not exist: %s", map_path)
	}

	m, err := bpf.LoadPinnedMap(map_path, nil)
	if err != nil {
		return fmt.Errorf("failed to load map: %w", err)
	}
	defer m.Close()

	iface, err := net.InterfaceByName(device)
	if err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	key := uint32(iface.Index)
	copy(opt.Device[:], device)

	if err := m.Put(key, opt); err != nil {
		return fmt.Errorf("failed to update map: %w", err)
	}

	return nil
}

func dump() {
	fs := flag.NewFlagSet("dump", flag.ExitOnError)
	mflag := fs.String("map", MAP_CONF, "Path to pinned eBPF map")
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}
	map_path := *mflag
	if _, err := os.Stat(map_path); os.IsNotExist(err) {
		log.Fatalf("map path does not exist: %s", map_path)
	}

	m, err := bpf.LoadPinnedMap(map_path, nil)
	if err != nil {
		log.Fatalf("failed to load map: %v", err)
	}
	defer m.Close()

	var entries []map[string]interface{}
	iterator := m.Iterate()
	var key uint32
	var value hopper_opt

	for iterator.Next(&key, &value) {
		device := strings.TrimRight(string(value.Device[:]), "\x00")
		entry := map[string]interface{}{
			"key":      key,
			"ifname":   device,
			"inbound":  value.P,
			"min_port": value.Min,
			"max_port": value.Max,
		}
		entries = append(entries, entry)
	}

	if err := iterator.Err(); err != nil {
		log.Fatalf("iteration failed: %v", err)
	}

	output, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal JSON: %v", err)
	}

	fmt.Println(string(output))
}

func config() {
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	inbound := fs.Uint("inbound", 0, "Inbound port to match (1-65535)")
	min := fs.Uint("min", 0, "Minimum port range (1-65535)")
	max := fs.Uint("max", 0, "Maximum port range (1-65535)")
	device := fs.String("device", "", "Interface name")
	map_path := fs.String("map", MAP_CONF, "Path to pinned eBPF map")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s %s:\n", os.Args[0], fs.Name())
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}

	switch {
	case *device == "":
		log.Fatal("missing --device")
	case strings.TrimSpace(*device) == "":
		log.Fatal("interface name cannot be empty")
	case *inbound == 0:
		log.Fatal("missing or invalid --inbound")
	case *min == 0 || *max == 0 || *min >= *max:
		log.Fatal("--min must be > 0 and less than --max")
	}

	opt := hopper_opt{P: uint16(*inbound), Min: uint16(*min), Max: uint16(*max)}
	if err := opt.update(*map_path, *device); err != nil {
		log.Fatalf("update failed: %v", err)
	}
}

func load() {
	must(os.MkdirAll(MAP_DIR, os.ModeDir))
	must(os.MkdirAll(PROG_DIR, os.ModeDir))
	must(os.MkdirAll(LINK_DIR, os.ModeDir))

	var objs hopperObjects
	must(loadHopperObjects(&objs, nil))
	defer objs.Close()

	must(objs.hopperMaps.Config.Pin(MAP_CONF))
	must(objs.hopperMaps.Logs.Pin(MAP_LOG))
	must(objs.hopperPrograms.TcPortHopperEgress.Pin(PROG_EGRESS))
	must(objs.hopperPrograms.TcPortHopperIngress.Pin(PROG_INGRESS))
}

func unload() {
	p, _ := bpf.LoadPinnedProgram(PROG_EGRESS, nil)
	if p != nil {
		p.Unpin()
		p.Close()
	}

	p, _ = bpf.LoadPinnedProgram(PROG_INGRESS, nil)
	if p != nil {
		p.Unpin()
		p.Close()
	}

	m, _ := bpf.LoadPinnedMap(MAP_LOG, nil)
	if m != nil {
		m.Unpin()
		m.Close()
	}

	m, _ = bpf.LoadPinnedMap(MAP_CONF, nil)
	if m != nil {
		m.Unpin()
		m.Close()
	}

	must(os.RemoveAll(HOP_BPF_DIR))
}

func _device_fl() *net.Interface {
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dev := fs.String("device", "", "Device to attach the program")
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}
	if *dev == "" {
		fs.Usage()
		log.Fatal("Specify the device!")
	}

	iface, err := net.InterfaceByName(*dev)
	must(err)

	return iface
}

func attach() {
	iface := _device_fl()
	p_ingress, err := bpf.LoadPinnedProgram(PROG_INGRESS, nil)
	must(err)
	defer p_ingress.Close()
	p_egress, err := bpf.LoadPinnedProgram(PROG_EGRESS, nil)
	must(err)
	defer p_egress.Close()

	tcnl, err := tc.Open(&tc.Config{})
	must(err)
	defer tcnl.Close()

	// Ensure clsact is enabled for tcx hooks
	tcnl.Qdisc().Add(&tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	})

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   p_ingress,
		Attach:    bpf.AttachTCXIngress,
	})
	must(err)
	defer l.Close()
	must(l.Pin(fmt.Sprintf("%s/%s-ingress", LINK_DIR, iface.Name)))

	l.Close()
	l, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   p_egress,
		Attach:    bpf.AttachTCXEgress,
	})
	must(err)
	must(l.Pin(fmt.Sprintf("%s/%s-egress", LINK_DIR, iface.Name)))
}

func detach() {
	iface := _device_fl()
	os.Remove(fmt.Sprintf("%s/%s-ingress", LINK_DIR, iface.Name))
	os.Remove(fmt.Sprintf("%s/%s-egress", LINK_DIR, iface.Name))
}

func tc_attach() {

	iface := _device_fl()

	p_ingress, err := bpf.LoadPinnedProgram(PROG_INGRESS, nil)
	must(err)
	defer p_ingress.Close()
	p_egress, err := bpf.LoadPinnedProgram(PROG_EGRESS, nil)
	must(err)
	defer p_egress.Close()

	tcnl, err := tc.Open(&tc.Config{})
	must(err)
	defer tcnl.Close()

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	tcnl.Qdisc().Add(&qdisc)
	fd := uint32(p_ingress.FD())
	flags := uint32(1)
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Handle:  0,
			Ifindex: uint32(iface.Index),
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	must(tcnl.Filter().Add(&filter))

	fd = uint32(p_egress.FD())
	filter.Msg.Parent = core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)

	must(tcnl.Filter().Add(&filter))
}

func tc_detach() {

	iface := _device_fl()

	cmd := exec.Command("/sbin/tc", "filter", "delete", "dev", iface.Name, "ingress")
	must(cmd.Run())

	cmd = exec.Command("/sbin/tc", "filter", "delete", "dev", iface.Name, "egress")
	must(cmd.Run())

	// For later fixes to use bare TC netlink

	// tcnl, err := tc.Open(&tc.Config{})
	// must(err)
	// defer tcnl.Close()

	// name := "tc_port_hoppedar_egress"
	// obj := tc.Object{
	// 	Msg: tc.Msg{
	// 		Family:  unix.AF_UNSPEC,
	// 		Ifindex: uint32(iface.Index),
	// 		Handle:  0x1,
	// 		Parent:  tc.HandleMinEgress,
	// 		Info:    (unix.ETH_P_ALL << 16),
	// 	},
	// 	Attribute: tc.Attribute{
	// 		Kind: "bpf",
	// 		BPF: &tc.Bpf{
	// 			Name: &name,
	// 		},
	// 	},
	// }

	// err = tcnl.Filter().Delete(&obj)
	// if err != nil {
	// 	log.Fatalf("Failed to delete filter: %v", err)
	// }

	// fmt.Println("Deleted BPF filter with handle", 0x1)

}

func print_event(event *hopperEvent) {
	ifname := "NA"
	if iface, err := net.InterfaceByIndex(int(event.Ifindex)); err == nil {
		ifname = iface.Name
	}

	ip := func(addr uint32) string {
		return net.IPv4(
			byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr),
		).String()
	}

	convertPort := func(port uint16) uint16 {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], port)
		return binary.LittleEndian.Uint16(b[:])
	}

	fmt.Printf(
		"Interface: %s, IP src: %s, IP dest: %s, Port src %d, Port dest %d, Altered Port %d\n",
		ifname,
		ip(event.Ipv4Src),
		ip(event.Ipv4Dest),
		convertPort(event.PortSrc),
		convertPort(event.PortDest),
		convertPort(event.PortAlter),
	)
}

func tail() {
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	map_file := fs.String("map", MAP_LOG, "Logs ring buffer map path")

	must(fs.Parse(os.Args[2:]))

	if *map_file == "" {
		fs.Usage()
		log.Fatal("Specify the map path!")
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	m, err := bpf.LoadPinnedMap(*map_file, nil)
	must(err)
	defer m.Clone()

	rd, err := ringbuf.NewReader(m)
	must(err)
	defer rd.Close()

	go func() {
		<-stopper
		must(rd.Close())
	}()

	log.Println("Waiting for events..")

	var event hopperEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		print_event(&event)
	}

}
