// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import "testing"

// Packets to one destination keep to one relay queue, so one worker sends a
// flow in order; different destinations spread over all the queues.
func TestRelayQueueIsStablePerDestAndSpreadsDests(t *testing.T) {
	t.Parallel()
	s := New()
	if len(s.relayChs) != relayWorkerCount() {
		t.Fatalf("%d relay queues, want one per worker (%d)", len(s.relayChs), relayWorkerCount())
	}
	total := 0
	for _, q := range s.relayChs {
		total += cap(q)
	}
	if total > relayQueueSize || total < relayQueueSize-len(s.relayChs) {
		t.Fatalf("relay queues hold %d jobs in total, want relayQueueSize (%d) split across them", total, relayQueueSize)
	}

	q := s.relayQueueFor(2002)
	for i := 0; i < 100; i++ {
		if s.relayQueueFor(2002) != q {
			t.Fatal("the same destination was given a different queue")
		}
	}

	// 8000 destinations spread within 2x of an even split over the workers.
	used := make(map[chan relayJob]int)
	const dests = 8000
	for i := uint32(0); i < dests; i++ {
		used[s.relayQueueFor(100000+i)]++
	}
	if len(used) != len(s.relayChs) {
		t.Fatalf("%d destinations used %d of %d queues", dests, len(used), len(s.relayChs))
	}
	fair := dests / len(s.relayChs)
	for _, n := range used {
		if n < fair/2 || n > fair*2 {
			t.Fatalf("a queue got %d of %d destinations, want about %d each", n, dests, fair)
		}
	}
}
