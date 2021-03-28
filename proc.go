package main

import (
	"errors"
	"log"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/zyedidia/tzu/ptrace"
	"golang.org/x/sys/unix"
)

type ProcState int

type ExitFunc func() error

const (
	PSysEnter ProcState = iota
	PSysExit
)

type Proc struct {
	tracer *ptrace.Tracer
	state  ProcState
	exited bool
	stack  *FuncStack
	fds    map[int]string
}

func startProc(target string, args []string) (*Proc, error) {
	cmd := exec.Command(target, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}

	err := cmd.Start()
	if err != nil {
		return nil, err
	}
	// wait for execve
	cmd.Wait()

	options := unix.PTRACE_O_EXITKILL | unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACEEXIT

	p, err := newTracedProc(cmd.Process.Pid)
	if err != nil {
		return nil, err
	}
	err = p.tracer.ReAttachAndContinue(options)
	if err != nil {
		return nil, err
	}

	// Wait for the initial SIGTRAP created because we are attaching
	// with ReAttachAndContinue to properly handle group stops.
	var ws unix.WaitStatus
	_, err = unix.Wait4(p.tracer.Pid(), &ws, 0, nil)
	if err != nil {
		return nil, err
	} else if ws.StopSignal() != unix.SIGTRAP {
		return nil, errors.New("wait: received non SIGTRAP: " + ws.StopSignal().String())
	}
	err = p.cont(0, false)

	return p, err

}

// Begins tracing an already existing process
func newTracedProc(pid int) (*Proc, error) {
	p := &Proc{
		tracer: ptrace.NewTracer(pid),
		stack:  NewStack(),
		fds:    make(map[int]string),
	}

	return p, nil
}

func (p *Proc) handleInterrupt() error {
	switch p.state {
	case PSysEnter:
		p.state = PSysExit
		f, err := p.syscallEnter()
		if err != nil || f == nil {
			return err
		}
		p.stack.Push(f)
	case PSysExit:
		p.state = PSysEnter
		var f ExitFunc
		if p.stack.Size() > 0 {
			f = p.stack.Pop()
		}
		if f != nil {
			return f()
		}
	}
	return nil
}

type strat int

const (
	stratSilence strat = iota
	stratRandBuf
	stratRandOff
)

func (s strat) String() string {
	switch s {
	case stratSilence:
		return "silence"
	case stratRandBuf:
		return "randomize buffer"
	case stratRandOff:
		return "randomize file offset"
	}
	return ""
}

const unpredictability = 0

func modifyBuf(data []byte) []byte {
	// randomize 10 bytes
	const nbytes = 10
	for n := 0; n < nbytes; n++ {
		i := rand.Intn(len(data))
		b := byte(rand.Intn(256))
		data[i] = b
	}
	return data
}

func (p *Proc) syscallEnter() (ExitFunc, error) {
	var regs unix.PtraceRegs
	p.tracer.GetRegs(&regs)

	switch regs.Orig_rax {
	case unix.SYS_OPEN, unix.SYS_OPENAT:
		var path string
		var err error
		switch regs.Orig_rax {
		case unix.SYS_OPEN:
			path, err = p.tracer.ReadCString(uintptr(regs.Rdi))
		case unix.SYS_OPENAT:
			path, err = p.tracer.ReadCString(uintptr(regs.Rsi))
		}
		if err != nil {
			return nil, err
		}
		return func() error {
			var exitRegs unix.PtraceRegs
			p.tracer.GetRegs(&exitRegs)
			fd := int(exitRegs.Rax)
			if fd < 0 {
				return nil
			}
			p.fds[fd] = path
			return nil
		}, nil
	}

	sample := rand.Intn(100)
	if sample >= unpredictability {
		// we are only unpredictable if the sample is below the threshold.
		return nil, nil
	}

	switch regs.Orig_rax {
	case unix.SYS_READ, unix.SYS_WRITE:
		filename := p.fds[int(regs.Rdi)]

		if strings.HasPrefix(filename, "/lib") || strings.HasPrefix(filename, "/usr/lib") {
			// don't mess with files being read from "/lib"
			return nil, nil
		}

		strategy := strat(rand.Intn(3))

		op := "write"
		if regs.Orig_rax == unix.SYS_READ {
			op = "read"
		}
		logger.Printf("%s %s(%d, %x, %d)\n", strategy, op, regs.Rdi, regs.Rsi, regs.Rdx)
		logger.Printf("Reading/writing: %s\n", p.fds[int(regs.Rdi)])

		switch strategy {
		case stratSilence:
			// read no bytes
			return p.SyscallSilence(&regs, regs.Rdx), nil
		case stratRandBuf:
			return nil, p.SyscallChangeBuf(&regs)
		case stratRandOff:
			return p.SyscallSeek(&regs, int(regs.Rdi), -10, 10), nil
		}
	case unix.SYS_SENDMSG:
	case unix.SYS_RECVMSG:
	case unix.SYS_NANOSLEEP:
		// strategy 3: increase wait time
		t := time.Duration(rand.Intn(int(1 * time.Millisecond)))
		log.Printf("sleeping an additional %v\n", t)
		time.Sleep(t)
	}
	return nil, nil
}

func randrange(min, max int) int {
	return rand.Intn(max-min) + min
}

func (p *Proc) SyscallSeek(regs *unix.PtraceRegs, fd int, min, max int) ExitFunc {
	origRegs := *regs
	newregs := unix.PtraceRegs{
		Orig_rax: unix.SYS_LSEEK,
		Rax:      unix.SYS_LSEEK,
		Rdi:      uint64(fd),
		Rsi:      uint64(randrange(min, max)),
		Rdx:      uint64(os.SEEK_CUR),
		R10:      0,
		R8:       0,
		R9:       0,
	}
	p.tracer.SetRegs(&newregs)

	return func() error {
		// reset %rip so we can replay the syscall that we interrupted
		// the syscall instruction is 2 bytes
		origRegs.Rip -= 2
		origRegs.Rax = origRegs.Orig_rax
		p.tracer.SetRegs(&origRegs)
		return nil
	}
}

func (p *Proc) SyscallBlock(regs *unix.PtraceRegs) ExitFunc {
	regs.Orig_rax = math.MaxUint64
	p.tracer.SetRegs(regs)
	return func() error {
		var exitRegs unix.PtraceRegs
		p.tracer.GetRegs(&exitRegs)
		perm := unix.EPERM
		exitRegs.Rax = uint64(-perm)
		return p.tracer.SetRegs(&exitRegs)
	}
}

func (p *Proc) SyscallChangeBuf(regs *unix.PtraceRegs) error {
	buf := regs.Rsi
	length := regs.Rdx
	data := make([]byte, length)
	n, err := p.tracer.ReadVM(uintptr(buf), data)
	if err != nil {
		return err
	}
	if n != int(length) {
		return errors.New("unable to read entire buffer")
	}
	data = modifyBuf(data)
	// use PokeData so we are guaranteed to have permissions
	p.tracer.PokeData(uintptr(buf), data)
	regs.Rdx = uint64(len(data))
	p.tracer.SetRegs(regs)
	return nil
}

func (p *Proc) SyscallSilence(regs *unix.PtraceRegs, ret uint64) ExitFunc {
	regs.Orig_rax = math.MaxUint64
	p.tracer.SetRegs(regs)
	return func() error {
		var exitRegs unix.PtraceRegs
		p.tracer.GetRegs(&exitRegs)
		exitRegs.Rax = ret
		return p.tracer.SetRegs(&exitRegs)
	}
}

func (p *Proc) exit() {
	p.exited = true
}

func (p *Proc) Exited() bool {
	return p.exited
}

func (p *Proc) cont(sig unix.Signal, groupStop bool) error {
	if groupStop {
		return p.tracer.Listen()
	}
	return p.tracer.Syscall(sig)
}

func (p *Proc) Pid() int {
	return p.tracer.Pid()
}
