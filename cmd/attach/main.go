package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Keep in sync with bpf/headers/goroutine.h
// Matches bpf/headers/goroutine.h layout (24 bytes total):
//
// struct goroutine_execute_data {
//   enum goroutine_state state; // u32 at offset 0
//   unsigned long goid;         // u64 at offset 8 (with 4-byte pad)
//   int pid;                    // u32 at offset 16
//   int tgid;                   // u32 at offset 20
// };
//
// We decode manually to avoid struct packing issues.

var goroutineState = []string{
	"IDLE",            // 0
	"RUNNABLE",        // 1
	"RUNNING",         // 2
	"SYSCALL",         // 3
	"WAITING",         // 4
	"MORIBUND_UNUSED", // 5
	"DEAD",            // 6
	"ENQUEUE_UNUSED",  // 7
	"COPYSTACK",       // 8
	"PREEMPTED",       // 9
}

func stateToString(s uint32) string {
	if int(s) < len(goroutineState) {
		return goroutineState[s]
	}
	return fmt.Sprintf("UNKNOWN(%d)", s)
}

func main() {
	var (
		binPath string
		symbol  string
		objPath string
		pid     int
		dedup   bool
	)
	flag.StringVar(&binPath, "bin", "./main", "Path to the Go server binary to attach")
	flag.StringVar(&symbol, "sym", "runtime.casgstatus", "Symbol name to attach uprobe to")
	flag.StringVar(&objPath, "obj", "./main.bpf.o", "Path to compiled BPF object")
	flag.IntVar(&pid, "pid", 0, "Attach only to this PID (0 = all for binary)")
	flag.BoolVar(&dedup, "dedup", true, "Suppress consecutive duplicate states per goid")
	flag.Parse()

	// Load the compiled BPF object and find program/map by name
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["uprobe_runtime_casgstatus"]
	if !ok {
		log.Fatalf("program not found: uprobe_runtime_casgstatus")
	}

	rbMap, ok := coll.Maps["rb"]
	if !ok {
		log.Fatalf("ringbuf map not found: rb")
	}

	exe, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("open executable: %v", err)
	}
	var up link.Link
	if pid > 0 {
		up, err = exe.Uprobe(symbol, prog, &link.UprobeOptions{PID: pid})
	} else {
		up, err = exe.Uprobe(symbol, prog, nil)
	}
	if err != nil {
		log.Fatalf("attach uprobe: %v", err)
	}
	defer up.Close()

	rd, err := ringbuf.NewReader(rbMap)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	fmt.Printf("Attached uprobe %s -> %s; reading ring buffer...\n", symbol, binPath)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	last := make(map[uint64]uint32)
	for {
		select {
		case <-sigs:
			fmt.Println("signal received; exiting")
			return
		default:
			rec, err := rd.Read()
			if err != nil {
				continue
			}
			b := rec.RawSample
			if len(b) < 24 {
				fmt.Printf("short sample: %d bytes\n", len(b))
				continue
			}
			state := uint32(binary.LittleEndian.Uint32(b[0:4]))
			// 4 bytes padding here (offset 4..7)
			goid := binary.LittleEndian.Uint64(b[8:16])
			pid := binary.LittleEndian.Uint32(b[16:20])
			tgid := binary.LittleEndian.Uint32(b[20:24])
			if dedup {
				if prev, ok := last[goid]; ok && prev == state {
					continue
				}
				last[goid] = state
			}
			fmt.Printf("pid=%d tgid=%d goid=%d state=%s (%d) (raw=%d bytes)\n", pid, tgid, goid, stateToString(state), state, len(b))
		}
	}
}
