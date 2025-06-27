package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	bpf "github.com/cilium/ebpf"
)

const (
	IF_NAMESIZE = 16
	CONF_MAP    = "/sys/fs/bpf/hopper/map/config"
)

type hopper_opt struct {
	P      uint16
	Min    uint16
	Max    uint16
	Ifname [IF_NAMESIZE]byte
}

func help() {
	fmt.Fprintln(os.Stderr, "Usage: hopper <command> [options]")
	fmt.Fprintln(os.Stderr, "Commands: config, dump")
	fmt.Fprintln(os.Stderr, "  config --ifname <interface> --inbound N --min N --max N [--map PATH]")
	fmt.Fprintln(os.Stderr, "  dump [--map PATH]")
	os.Exit(1)
}

func (opt *hopper_opt) update(map_path, ifname string) error {
	if len(ifname) > IF_NAMESIZE {
		return fmt.Errorf("interface name too long: %s", ifname)
	}

	if _, err := os.Stat(map_path); os.IsNotExist(err) {
		return fmt.Errorf("map path does not exist: %s", map_path)
	}

	m, err := bpf.LoadPinnedMap(map_path, nil)
	if err != nil {
		return fmt.Errorf("failed to load map: %w", err)
	}
	defer m.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("invalid interface: %w", err)
	}

	key := uint32(iface.Index)
	copy(opt.Ifname[:], ifname)

	if err := m.Put(key, opt); err != nil {
		return fmt.Errorf("failed to update map: %w", err)
	}

	return nil
}

func dump(map_path string) {
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
		ifname := strings.TrimRight(string(value.Ifname[:]), "\x00")
		entry := map[string]interface{}{
			"key":      key,
			"ifname":   ifname,
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
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	inbound := fs.Uint("inbound", 0, "Inbound port to match (1-65535)")
	min := fs.Uint("min", 0, "Minimum port range (1-65535)")
	max := fs.Uint("max", 0, "Maximum port range (1-65535)")
	ifname := fs.String("ifname", "", "Interface name")
	map_path := fs.String("map", CONF_MAP, "Path to pinned eBPF map")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s %s:\n", os.Args[0], fs.Name())
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}

	switch {
	case *ifname == "":
		log.Fatal("missing --ifname")
	case strings.TrimSpace(*ifname) == "":
		log.Fatal("interface name cannot be empty")
	case *inbound == 0:
		log.Fatal("missing or invalid --inbound")
	case *min == 0 || *max == 0 || *min >= *max:
		log.Fatal("--min must be > 0 and less than --max")
	}

	opt := hopper_opt{P: uint16(*inbound), Min: uint16(*min), Max: uint16(*max)}
	if err := opt.update(*map_path, *ifname); err != nil {
		log.Fatalf("update failed: %v", err)
	}

	fmt.Println("Successfully updated")
}

func main() {
	if len(os.Args) < 2 {
		help()
	}

	switch os.Args[1] {
	case "config":
		config()
	case "dump":
		fs := flag.NewFlagSet("dump", flag.ExitOnError)
		map_path := fs.String("map", CONF_MAP, "Path to pinned eBPF map")
		if err := fs.Parse(os.Args[2:]); err != nil {
			log.Fatalf("failed to parse flags: %v", err)
		}
		dump(*map_path)
	default:
		help()
	}
}
