package main

type Strategy int

const (
	StratSilence Strategy = iota
	StratRandBuf
	StratRandOff
)

func (s Strategy) String() string {
	switch s {
	case StratSilence:
		return "silence"
	case StratRandBuf:
		return "randomize buffer"
	case StratRandOff:
		return "randomize file offset"
	}
	return ""
}
