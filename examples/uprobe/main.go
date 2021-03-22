// This program demonstrates how to attach an eBPF program to a uretprobe.
// The program will be attached to the 'readline' symbol in the binary '/bin/bash' and print out
// the line which 'readline' functions returns to the caller.
package main

import (
	"bytes"
	"io/ioutil"
	"strconv"
	"strings"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	ringbuffer "github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 -target bpf -tags linux UProbeExample ./bpf/uprobe_example.c -- -I../headers -O2

const bashPath = "/bin/bash"
const symbolName = "readline"

type Event struct {
	Pid  uint32
	Line [80]byte
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	specs, err := LoadUProbeExample()
	if err != nil {
		log.Fatalf("failed to load uprobe %v", err)
	}

	var objs UProbeExampleObjects
	if err := specs.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
		},
	}); err != nil {
		log.Fatalf("failed to load and assign %v", err)
	}

	binbashes := []string{
		bashPath,
	}

	oneSuccess := false
	var lastErr error
	for id, bash := range binbashes {
		detachUprobe, err := attachUprobe(objs.BashReadline, bash, symbolName, fmt.Sprintf("binbash_%v", id))
		if err != nil {
			log.Printf("Failed to attach Uprobe %v", err)
			lastErr = err
			continue
		}
		defer detachUprobe()
		oneSuccess = true
	}
	if !oneSuccess {
		log.Fatalf("all Uprobe attaches failed %v", lastErr)
	}

	rd, err := ringbuffer.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("error while createing ringbuffer reader %v", err)
	}
	defer func() {
		_ = rd.Close()
	}()

	go func() {
		var event Event
		for {
			select {
			case <-stopper:
				return
			default:
			}
			record, err := rd.Read()
			if err != nil {
				if ringbuffer.IsClosed(err) {
					return
				}
				log.Printf("Failed to read from ringbuffer %v", err)
			}
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("Failed to read record %v", err)
			}
			line := string(event.Line[:bytes.IndexByte(event.Line[:], 0)])
			log.Printf("BASHREADLINE %v", line)
		}
	}()

	<-stopper
}

func attachUprobe(program *ebpf.Program, elfPath, symbolName, probeName string) (func(), error) {
	sa, err := getSymbolAddress(elfPath, symbolName)
	if err != nil {
		log.Printf("error while getting symbol address %v", err)
		return nil, err
	}
	if err := createUProbe(probeName, elfPath, sa, true); err != nil {
		log.Printf("create uprobe error %v", err)
		return nil, err
	}

	probeID, err := getUProbeID(probeName)
	if err != nil {
		log.Printf("get uprobe id failure %v", err)
		return nil, err
	}
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      probeID,
		Sample_type: unix.PERF_SAMPLE_RAW | unix.PERF_SAMPLE_CALLCHAIN,
		Sample:      1,
		Wakeup:      1,
		Read_format: 0,
	}
	pfd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC|unix.PERF_FLAG_FD_NO_GROUP)
	if err != nil {
		log.Printf("unable to open perf event %v", err)
		return nil, err
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(program.FD())); errno != 0 {
		log.Printf("unable to set BPF perf prog %v", err)
		return nil, err
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(pfd), unix.PERF_EVENT_IOC_ENABLE, 0); errno != 0 {
		log.Printf("unable to enable perf event %v", err)
		return nil, err
	}

	log.Printf("uprobe attached")
	return func() {
		if err := deleteUProbe(probeName); err != nil {
			log.Printf("Failed to detach Uprobe")
		} else {
			log.Printf("Uprobe Detached successfully")
		}
	}, nil
}

func deleteUProbe(name string) error {
	msg := fmt.Sprintf("-:%s", name)
	return writeUprobeEvents(msg)
}

func getUProbeID(name string) (uint64, error) {
	fname := fmt.Sprintf("/sys/kernel/debug/tracing/events/uprobes/%s/id", name)
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return 0, fmt.Errorf("failed to read tracepoint ID for '%s': %v", name, err)
	}
	tid := strings.TrimSuffix(string(data), "\n")
	return strconv.ParseUint(tid, 10, 64)
}

func createUProbe(name, binaryPath string, symbolAddress uint64, isReturn bool) error {
	probeType := "p"
	if isReturn {
		probeType = "r"
	}
	msg := fmt.Sprintf("%s:%s %s:0x%x", probeType, name, binaryPath, symbolAddress)
	fmt.Println("uprobe event", msg)

	return writeUprobeEvents(msg)
}

func writeUprobeEvents(msg string) error {
	f, err := os.OpenFile("/sys/kernel/debug/tracing/uprobe_events", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("fail opening")
		return err
	}
	log.Printf("start writing")
	if _, err := f.WriteString(msg); err != nil {
		log.Printf("fail writing: %v", err)
		return err
	}
	log.Printf("finish writing")
	return f.Close()
}

func getSymbolAddress(elfPath, symbolName string) (uint64, error) {
	binFile, err := elf.Open(elfPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open ELF: %+v", err)
	}
	defer func() {
		_ = binFile.Close()
	}()

	syms, err := binFile.DynamicSymbols()
	if err != nil {
		return 0, fmt.Errorf("failed to list symbols: %+v", err)
	}

	for _, sym := range syms {
		if sym.Name == symbolName {
			return sym.Value, nil
		}
	}

	return 0, fmt.Errorf("failed to find symbol %s", symbolName)
}
