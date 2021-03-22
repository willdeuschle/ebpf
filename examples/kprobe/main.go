// This program demonstrates how to attach an eBPF program to a kprobe.
// The program will be attached to the __x64_sys_execve syscall and print out
// the number of times it has been called every second.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"io/ioutil"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 -target bpf -tags linux KProbeExample ./bpf/kprobe_example.c -- -I../headers

const mapKey uint32 = 0

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

	specs, err := LoadKProbeExample()
	if err != nil {
		log.Fatalf("failed to load kprobe %v", err)
	}

	// Load Program and Map
	objs := KProbeExampleObjects{}
	if err := specs.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
		},
	}); err != nil {
		log.Fatalf("failed to load and assign %v", err)
	}

	// Create and attach __x64_sys_execve kprobe
    detachKprobe, err := attachKProbe(objs.KprobeExecve, "sys_execve", "sysexecve_probe")
    if err != nil {
        log.Fatalf("Failed to create and attach kprobe %v", err)
    }
    defer detachKprobe()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
				log.Fatalf("error while reading map: %v", err)
			}
			log.Printf("__x64_sys_execve called %d times\n", value)
		case <-stopper:
			return
		}
	}
}

func attachKProbe(program *ebpf.Program, syscall, probeName string) (func(), error) {
	if err := createKProbe(syscall, probeName, true); err != nil {
		log.Printf("create kprobe error %v", err)
		return nil, err
	}

	probeID, err := getKProbeID(probeName)
	if err != nil {
		log.Printf("get kprobe id failure %v", err)
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

	log.Printf("kprobe attached")
	return func() {
		if err := deleteKProbe(probeName); err != nil {
			log.Printf("Failed to detach kprobe")
		} else {
			log.Printf("kprobe detached successfully")
		}
	}, nil
}

func deleteKProbe(name string) error {
	msg := fmt.Sprintf("-:%s", name)
	return writeKProbeEvents(msg)
}

func getKProbeID(name string) (uint64, error) {
	fname := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", name)
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return 0, fmt.Errorf("failed to read tracepoint ID for '%s': %v", name, err)
	}
	tid := strings.TrimSuffix(string(data), "\n")
	return strconv.ParseUint(tid, 10, 64)
}

func createKProbe(syscall, probeName string, isReturn bool) error {
	probeType := "p"
	if isReturn {
		probeType = "r"
	}
	msg := fmt.Sprintf("%s:%s %s", probeType, probeName, syscall)
	fmt.Println("kprobe event", msg)

	return writeKProbeEvents(msg)
}

func writeKProbeEvents(msg string) error {
	f, err := os.OpenFile("/sys/kernel/debug/tracing/kprobe_events", os.O_APPEND|os.O_WRONLY, 0644)
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