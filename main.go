package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"time"

	"github.com/jessevdk/go-flags"
)

func main() {
	runtime.LockOSThread()
	rand.Seed(time.Now().UTC().UnixNano())

	flagparser := flags.NewParser(&cliopts, flags.PassDoubleDash|flags.PrintErrors)
	flagparser.Usage = "[OPTIONS] COMMAND [ARGS]"
	args, err := flagparser.Parse()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if cliopts.Verbose {
		SetLogger(log.New(os.Stdout, "INFO: ", 0))
	}

	if len(args) <= 0 || cliopts.Help {
		flagparser.WriteHelp(os.Stdout)
		os.Exit(0)
	}

	target := args[0]
	args = args[1:]

	opts := Options{
		Unpredictability: cliopts.Unpredictability,
		RandBuf:          MustParseRange(cliopts.ModBytes),
		RandFp:           MustParseRange(cliopts.OffRange),
		Wait:             MustParseRange(cliopts.WaitRange),
		IOStrategies:     []Strategy{StratSilence, StratRandBuf, StratRandOff},
	}

	prog, _, err := NewProgram(target, args, opts)
	if err != nil {
		log.Fatal(err)
	}

	var s Status
	for {
		p, err := prog.Wait(&s)
		if err == ErrFinishedTrace {
			break
		}
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
