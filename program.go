package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

var ErrFinishedTrace = errors.New("tracing finished")

// Status represents a return status from a call to Wait.
type Status struct {
	unix.WaitStatus

	sig       unix.Signal
	groupStop bool
}

type Program struct {
	procs map[int]*Proc
}

func NewProgram(target string, args []string) (*Program, int, error) {
	proc, err := startProc(target, args)
	if err != nil {
		return nil, 0, err
	}

	prog := new(Program)
	prog.procs = map[int]*Proc{
		proc.Pid(): proc,
	}

	return prog, proc.Pid(), err
}

func (p *Program) Wait(status *Status) (*Proc, error) {
	ws := &status.WaitStatus

	wpid, err := unix.Wait4(-1, ws, 0, nil)
	if err != nil {
		return nil, err
	}

	status.sig = 0
	status.groupStop = false
	proc, ok := p.procs[wpid]
	if !ok {
		proc, err = newTracedProc(wpid)
		if err != nil {
			return nil, err
		}
		p.procs[wpid] = proc
		logger.Printf("%d: new process created (tracing enabled)\n", wpid)
		return proc, nil
	}

	if ws.Exited() || ws.Signaled() {
		logger.Printf("%d: exited\n", wpid)
		delete(p.procs, wpid)
		proc.exit()

		if len(p.procs) == 0 {
			return proc, ErrFinishedTrace
		}
	} else if !ws.Stopped() {
		logger.Printf("%d: not stopped?\n", wpid)
		return proc, nil
	} else if ws.StopSignal() == (unix.SIGTRAP | 0x80) {
		// var regs unix.PtraceRegs
		// proc.tracer.GetRegs(&regs)
		// logger.Printf("%d: syscall %d\n", wpid, regs.Orig_rax)
		proc.handleInterrupt()
	} else if ws.StopSignal() != unix.SIGTRAP {
		if statusPtraceEventStop(*ws) {
			status.groupStop = true
			logger.Printf("%d: received group stop\n", wpid)
		} else {
			logger.Printf("%d: received signal '%s'\n", wpid, ws.StopSignal())
			status.sig = ws.StopSignal()
		}
	} else if ws.TrapCause() == unix.PTRACE_EVENT_CLONE {
		newpid, err := proc.tracer.GetEventMsg()
		logger.Printf("%d: called clone() = %d (err=%v)\n", wpid, newpid, err)
	} else if ws.TrapCause() == unix.PTRACE_EVENT_FORK {
		logger.Printf("%d: called fork()\n", wpid)
	} else if ws.TrapCause() == unix.PTRACE_EVENT_VFORK {
		logger.Printf("%d: called vfork()\n", wpid)
	} else if ws.TrapCause() == unix.PTRACE_EVENT_EXEC {
		logger.Printf("%d: called exit()\n", wpid)
		delete(p.procs, wpid)
		proc.exit()
	} else {
		// status.sig = ws.StopSignal()
		logger.Printf("%d: other signal?: %v\n", wpid, status.sig)
	}
	return proc, nil
}

// Continue resumes execution of the given process. The wait status must be
// passed to replay any signals that were received while waiting.
func (p *Program) Continue(pr *Proc, status Status) error {
	return pr.cont(status.sig, status.groupStop)
}

func statusPtraceEventStop(status unix.WaitStatus) bool {
	return int(status)>>16 == unix.PTRACE_EVENT_STOP
}
