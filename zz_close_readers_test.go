// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"runtime"
	"testing"
	"time"
)

// TestCloseStopsReaders: Close ends every UDP reader. On Linux the
// recvmmsg path wraps the closed-socket error twice, which the old check
// (the inner error's exact text) never matched, so all 2×NumCPU readers
// kept spinning on their closed sockets for the life of the process.
func TestCloseStopsReaders(t *testing.T) {
	runtime.GC()
	base := runtime.NumGoroutine()

	s := New()
	go func() { _ = s.ListenAndServe("127.0.0.1:0") }()
	select {
	case <-s.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("beacon did not start")
	}
	time.Sleep(100 * time.Millisecond)
	running := runtime.NumGoroutine()

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= base+2 {
			t.Logf("goroutines: base=%d running=%d after Close=%d", base, running, n)
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			t.Fatalf("goroutines still running after Close: base=%d running=%d now=%d\n%s",
				base, running, n, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(20 * time.Millisecond)
	}
}
