// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64 || wasm

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"structs"

	"github.com/cilium/ebpf"
)

type hopperEvent struct {
	_         structs.HostLayout
	Ifindex   uint32
	Ipv4Src   uint32
	Ipv4Dest  uint32
	PortSrc   uint16
	PortDest  uint16
	PortAlter uint16
	_         [2]byte
}

type hopperHopperOpt struct {
	_    structs.HostLayout
	InP  uint16
	MinP uint16
	MaxP uint16
}

// loadHopper returns the embedded CollectionSpec for hopper.
func loadHopper() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_HopperBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load hopper: %w", err)
	}

	return spec, err
}

// loadHopperObjects loads hopper and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*hopperObjects
//	*hopperPrograms
//	*hopperMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadHopperObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadHopper()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// hopperSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hopperSpecs struct {
	hopperProgramSpecs
	hopperMapSpecs
	hopperVariableSpecs
}

// hopperProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hopperProgramSpecs struct {
	TcPortHopperEgress  *ebpf.ProgramSpec `ebpf:"tc_port_hopper_egress"`
	TcPortHopperIngress *ebpf.ProgramSpec `ebpf:"tc_port_hopper_ingress"`
}

// hopperMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hopperMapSpecs struct {
	Config *ebpf.MapSpec `ebpf:"config"`
	Logs   *ebpf.MapSpec `ebpf:"logs"`
}

// hopperVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type hopperVariableSpecs struct {
	Unused *ebpf.VariableSpec `ebpf:"unused"`
}

// hopperObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadHopperObjects or ebpf.CollectionSpec.LoadAndAssign.
type hopperObjects struct {
	hopperPrograms
	hopperMaps
	hopperVariables
}

func (o *hopperObjects) Close() error {
	return _HopperClose(
		&o.hopperPrograms,
		&o.hopperMaps,
	)
}

// hopperMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadHopperObjects or ebpf.CollectionSpec.LoadAndAssign.
type hopperMaps struct {
	Config *ebpf.Map `ebpf:"config"`
	Logs   *ebpf.Map `ebpf:"logs"`
}

func (m *hopperMaps) Close() error {
	return _HopperClose(
		m.Config,
		m.Logs,
	)
}

// hopperVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadHopperObjects or ebpf.CollectionSpec.LoadAndAssign.
type hopperVariables struct {
	Unused *ebpf.Variable `ebpf:"unused"`
}

// hopperPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadHopperObjects or ebpf.CollectionSpec.LoadAndAssign.
type hopperPrograms struct {
	TcPortHopperEgress  *ebpf.Program `ebpf:"tc_port_hopper_egress"`
	TcPortHopperIngress *ebpf.Program `ebpf:"tc_port_hopper_ingress"`
}

func (p *hopperPrograms) Close() error {
	return _HopperClose(
		p.TcPortHopperEgress,
		p.TcPortHopperIngress,
	)
}

func _HopperClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed hopper_bpfel.o
var _HopperBytes []byte
