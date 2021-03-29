package main

import (
	"errors"
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
	opts   *Options
}

func startProc(target string, args []string, opts *Options) (*Proc, error) {
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

	p, err := newTracedProc(cmd.Process.Pid, opts)
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
func newTracedProc(pid int, opts *Options) (*Proc, error) {
	p := &Proc{
		tracer: ptrace.NewTracer(pid),
		stack:  NewStack(),
		fds:    make(map[int]string),
		opts:   opts,
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

func modifyBuf(data []byte, nrand int) []byte {
	// randomize nrand bytes
	for n := 0; n < nrand; n++ {
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
	case unix.SYS_CLOSE:
		fd := int(regs.Rdi)
		if _, ok := p.fds[fd]; ok {
			delete(p.fds, fd)
			return nil, nil
		}
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

	sample := rand.Float64()
	if sample >= p.opts.Unpredictability {
		// we are unpredictable only if the sample is below the threshold.
		return nil, nil
	}

	switch regs.Orig_rax {
	case unix.SYS_READ, unix.SYS_WRITE:
		filename := p.fds[int(regs.Rdi)]

		if strings.HasPrefix(filename, "/lib") || strings.HasPrefix(filename, "/usr/lib") {
			// don't mess with files being read from "/lib"
			return nil, nil
		}

		// pick random strategy
		strategy := p.opts.IOStrategies[rand.Intn(len(p.opts.IOStrategies))]

		op := "write"
		if regs.Orig_rax == unix.SYS_READ {
			op = "read"
		}
		logger.Printf("%s %s(%d, %x, %d)\n", strategy, op, regs.Rdi, regs.Rsi, regs.Rdx)
		logger.Printf("Reading/writing: %s\n", p.fds[int(regs.Rdi)])

		switch strategy {
		case StratSilence:
			// read no bytes
			return p.SyscallSilence(&regs, regs.Rdx), nil
		case StratRandBuf:
			err := p.SyscallChangeBuf(regs.Rsi, regs.Rdx, &regs.Rdx)
			p.tracer.SetRegs(&regs)
			return nil, err
		case StratRandOff:
			return p.SyscallSeek(&regs, int(regs.Rdi)), nil
		}
	case unix.SYS_SENDTO, unix.SYS_RECVFROM:
		logger.Printf("Changing buffer in sendto/recvfrom")
		err := p.SyscallChangeBuf(regs.Rsi, regs.Rdx, &regs.Rdx)
		p.tracer.SetRegs(&regs)
		return nil, err
	case unix.SYS_NANOSLEEP:
		// strategy 3: increase wait time
		t := time.Duration(time.Duration(p.opts.Wait.Get()) * time.Microsecond)
		logger.Printf("sleeping an additional %v\n", t)
		time.Sleep(t)
	}
	return nil, nil
}

func (p *Proc) SyscallSeek(regs *unix.PtraceRegs, fd int) ExitFunc {
	origRegs := *regs
	newregs := unix.PtraceRegs{
		Orig_rax: unix.SYS_LSEEK,
		Rax:      unix.SYS_LSEEK,
		Rdi:      uint64(fd),
		Rsi:      uint64(p.opts.RandFp.Get()),
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

func (p *Proc) SyscallChangeBuf(buf, length uint64, modlen *uint64) error {
	if buf == 0 {
		// buffer is null?
		return nil
	}

	data := make([]byte, length)
	n, err := p.tracer.ReadVM(uintptr(buf), data)
	if err != nil {
		return err
	}
	if n != int(length) {
		return errors.New("unable to read entire buffer")
	}
	data = modifyBuf(data, p.opts.RandBuf.Get())
	// use PokeData so we are guaranteed to have permissions
	p.tracer.PokeData(uintptr(buf), data)
	*modlen = uint64(len(data))
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
