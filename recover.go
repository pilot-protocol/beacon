// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"log/slog"
	"runtime/debug"
	"sync/atomic"
)

// recoveredPanicCount is a process-global counter incremented every time
// recoverHandler swallows a panic. Exposed via RecoveredPanicCount so the
// dashboard / Prom scrape can alert on a non-zero rate — a panic is still a
// bug and must be visible; it just must not take the process down. The
// beacon runs embedded in the registry binary, so an unrecovered panic on a
// packet-handling goroutine takes the whole trust root with it.
var recoveredPanicCount atomic.Uint64

// RecoveredPanicCount returns the total number of panics swallowed by
// recoverHandler since process start.
func RecoveredPanicCount() uint64 {
	return recoveredPanicCount.Load()
}

// recoverHandler is the standard panic-recovery shim placed at the top of
// every packet-handling and background-loop goroutine in this package.
// Mirrors the shim in rendezvous/accept. Usage:
//
//	defer recoverHandler("handlePacket")
//
// It must be the OUTERMOST defer in the function: defers run LIFO, so any
// mutex unlock / buffer return registered later still executes before the
// recover observes the panic.
func recoverHandler(label string) {
	r := recover()
	if r == nil {
		return
	}
	count := recoveredPanicCount.Add(1)
	slog.Error("beacon: panic recovered",
		"where", label,
		"panic", r,
		"recovered_total", count,
		"stack", string(debug.Stack()),
	)
}

// safely runs fn under recoverHandler. Used by the periodic background
// loops so one bad tick cannot retire the ticker goroutine.
func safely(label string, fn func()) {
	defer recoverHandler(label)
	fn()
}
