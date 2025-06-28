package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -verbose -target bpfel hopper bpf/hopper.bpf.c
import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	bpf "github.com/cilium/ebpf"
	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

const (
	IF_NAMESIZE  = 16
	HOP_BPF_DIR  = "/sys/fs/bpf/hopper/"
	MAP_DIR      = (HOP_BPF_DIR + "map/")
	MAP_CONF     = (MAP_DIR + "config")
	PROG_DIR     = (HOP_BPF_DIR + "prog/")
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
	case "legacy_attach":
		tc_attach()
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
	fmt.Fprintln(os.Stderr, "Commands: config, dump, load, unload, legacy_attach")
	fmt.Fprintln(os.Stderr, "  config --device <interface> --inbound N --min N --max N [--map PATH]")
	fmt.Fprintln(os.Stderr, "  dump [--map PATH]")
	fmt.Fprintln(os.Stderr, "  legacy_attach --device <interface>")
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

	var objs hopperObjects
	must(loadHopperObjects(&objs, nil))
	defer objs.Close()

	must(objs.hopperMaps.Config.Pin(MAP_CONF))
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

	m, _ := bpf.LoadPinnedMap(MAP_CONF, nil)
	if m != nil {
		m.Unpin()
		m.Close()
	}

	must(os.RemoveAll(HOP_BPF_DIR))
}

func tc_attach() {
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dev := fs.String("device", "", "Device to attach the program")
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}
	if *dev == "" {
		fs.Usage()
		log.Fatal("Specify the device!")
	}

	netif, err := net.InterfaceByName(*dev)
	must(err)

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
			Ifindex: uint32(netif.Index),
			Parent:  tc.HandleRoot,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	tcnl.Qdisc().Add(&qdisc)

	fd := uint32(p_ingress.FD())
	flags := uint32(0x1)
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(netif.Index),
			Handle:  0,
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
	filter.Attribute.BPF.FD = &fd
	filter.Msg.Parent = core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress)

	must(tcnl.Filter().Add(&filter))
}
