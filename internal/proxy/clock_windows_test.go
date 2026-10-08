package proxy

import (
	"syscall"
	"unsafe"
)

// Go's Windows time.Now reads the coarse shared interrupt clock. QPC avoids
// quantizing sub-millisecond latency samples to a whole scheduler tick.
var performanceCounter = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceCounter")
var performanceFrequency = func() int64 {
	var value int64
	query := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")
	if ok, _, err := query.Call(uintptr(unsafe.Pointer(&value))); ok == 0 {
		panic(err)
	}
	return value
}()

func benchmarkNow() int64 {
	var value int64
	if ok, _, err := performanceCounter.Call(uintptr(unsafe.Pointer(&value))); ok == 0 {
		panic(err)
	}
	return value
}

func benchmarkNanoseconds(delta int64) int64 { return delta * 1e9 / performanceFrequency }
