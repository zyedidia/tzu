package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"time"
)

func main() {
	runtime.LockOSThread()
	rand.Seed(time.Now().UTC().UnixNano())

	target := os.Args[1]
	args := os.Args[2:]

	SetLogger(log.New(os.Stdout, "", 0))

	prog, pid, err := NewProgram(target, args)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pid)

	var s Status
	for {
		p, err := prog.Wait(&s)
		if err != nil {
			log.Fatal(err)
		}

		if !p.Exited() {
			err = prog.Continue(p, s)
			if err != nil {
				fmt.Println(p.Pid(), err)
			}
		}
	}
}
