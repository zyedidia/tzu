package main

var cliopts struct {
	Unpredictability float64 `short:"u" default:"0.2" long:"unpredictability" description:"Fraction of calls where unpredictability is applied."`
	IOStrategies     string  `short:"s" long:"iostrats" description:"List of I/O strategies to use."`
	ModBytes         string  `short:"b" default:"5,15" long:"bufrange" description:"Number of bytes to randomly modify in strategy 2."`
	OffRange         string  `short:"f" default:"-10,10" long:"fprange" description:"Range for seeking from the current fp in strategy 4."`
	WaitRange        string  `short:"w" default:"1000" long:"waitrange" description:"Range of time to add for strategy 3 (microseconds)."`
	Verbose          bool    `short:"V" long:"verbose" description:"Show verbose debug information."`
	Help             bool    `short:"h" long:"help" description:"Show this help message."`
}
