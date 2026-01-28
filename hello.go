package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	b, err := bpf.NewModuleFromFile("hello.bpf.o")
	must(err)
	defer b.Close()

	must(b.BPFLoadObject())

	p, err := b.GetProgram("hello")
	must(err)

	_, err = p.AttachKprobe("__x64_sys_execve")
	must(err)

	fmt.Println("kprobe attached; streaming trace_pipe...")
	go tailTracePipe()
	waitForSignal()

	fmt.Println("Cleaning up")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func waitForSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func tailTracePipe() {
	const tracePipe = "/sys/kernel/debug/tracing/trace_pipe"
	f, err := os.Open(tracePipe)
	if err != nil {
		fmt.Printf("failed to open %s: %v\n", tracePipe, err)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("Hint: mount tracefs: sudo mount -t tracefs nodev /sys/kernel/debug/tracing")
		} else {
			fmt.Println("Hint: try running with sudo.")
		}
		return
	}
	defer f.Close()

	r := bufio.NewScanner(f)
	for r.Scan() {
		fmt.Println(r.Text())
	}
	if err := r.Err(); err != nil {
		fmt.Printf("trace_pipe read error: %v\n", err)
	}
}
