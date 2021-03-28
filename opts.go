package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
)

type Options struct {
	IOStrategies     []Strategy
	Unpredictability float64
	RandBuf          Range
	RandFp           Range
	Wait             Range
}

type Range struct {
	low, high int
}

func MustParseRange(s string) Range {
	r, err := ParseRange(s)
	if err != nil {
		log.Fatal(err)
	}
	return r
}

func ParseRange(s string) (Range, error) {
	if strings.Contains(s, ",") {
		splits := strings.Split(s, ",")
		if len(splits) < 2 {
			return Range{}, errors.New("invalid range")
		}
		low, err := strconv.Atoi(strings.TrimSpace(splits[0]))
		if err != nil {
			return Range{}, fmt.Errorf("invalid range: %w", err)
		}
		high, err := strconv.Atoi(strings.TrimSpace(splits[1]))
		if err != nil {
			return Range{}, fmt.Errorf("invalid range: %w", err)
		}
		return Range{
			low:  low,
			high: high,
		}, nil
	}
	low, err := strconv.Atoi(s)
	if err != nil {
		return Range{}, fmt.Errorf("invalid range: %w", err)
	}
	return Range{
		low:  low,
		high: low + 1,
	}, nil
}

func (r Range) Get() int {
	return rand.Intn(r.high-r.low) + r.low
}

// default is all strategies enabled and unpredictability of 20%.
var DefaultOptions = Options{
	IOStrategies:     []Strategy{StratSilence, StratRandBuf, StratRandOff},
	Unpredictability: 0.2,
	RandBuf:          Range{5, 15},
	RandFp:           Range{-10, 10},
}
