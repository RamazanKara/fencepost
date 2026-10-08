//go:build !windows

package proxy

import "time"

var benchmarkEpoch = time.Now()

func benchmarkNow() int64                    { return time.Since(benchmarkEpoch).Nanoseconds() }
func benchmarkNanoseconds(delta int64) int64 { return delta }
