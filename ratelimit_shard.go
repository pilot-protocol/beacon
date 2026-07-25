// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"sync"
	"time"
)

// rateLimitShards is the shard count for the per-packet rate limiters. A
// power of two so the shard index is a mask. Sized well above the reader
// goroutine count (2*NumCPU) so contention on any one shard stays rare
// even under a full-fleet reconverge flood.
const rateLimitShards = 256

func shardU32(k uint32) uint32 {
	return (k * 2654435761) & (rateLimitShards - 1)
}

func shardStr(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h & (rateLimitShards - 1)
}

// discoverRateLimiter is a sharded nodeID -> last-allowed-time map. Each
// shard carries its own mutex, so discovers for different node ids proceed
// in parallel instead of serialising on one global lock.
type discoverRateLimiter struct {
	shards [rateLimitShards]struct {
		mu sync.Mutex
		m  map[uint32]time.Time
	}
}

func newDiscoverRateLimiter() *discoverRateLimiter {
	rl := &discoverRateLimiter{}
	for i := range rl.shards {
		rl.shards[i].m = make(map[uint32]time.Time)
	}
	return rl
}

// allow reports whether a discover endpoint update for nodeID is permitted
// now, recording the timestamp when it is.
func (rl *discoverRateLimiter) allow(nodeID uint32, minInterval time.Duration) bool {
	sh := &rl.shards[shardU32(nodeID)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if last, ok := sh.m[nodeID]; ok && time.Since(last) < minInterval {
		return false
	}
	sh.m[nodeID] = time.Now()
	return true
}

func (rl *discoverRateLimiter) sweep(cutoff time.Time) {
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		for id, last := range sh.m {
			if last.Before(cutoff) {
				delete(sh.m, id)
			}
		}
		sh.mu.Unlock()
	}
}

// punchRateLimiter is a sharded source-IP -> last-allowed-time map.
type punchRateLimiter struct {
	shards [rateLimitShards]struct {
		mu sync.Mutex
		m  map[string]time.Time
	}
}

func newPunchRateLimiter() *punchRateLimiter {
	rl := &punchRateLimiter{}
	for i := range rl.shards {
		rl.shards[i].m = make(map[string]time.Time)
	}
	return rl
}

func (rl *punchRateLimiter) allow(sourceKey string, minInterval time.Duration) bool {
	sh := &rl.shards[shardStr(sourceKey)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if last, ok := sh.m[sourceKey]; ok && time.Since(last) < minInterval {
		return false
	}
	sh.m[sourceKey] = time.Now()
	return true
}

func (rl *punchRateLimiter) sweep(cutoff time.Time) {
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		for ip, last := range sh.m {
			if last.Before(cutoff) {
				delete(sh.m, ip)
			}
		}
		sh.mu.Unlock()
	}
}

// relayRateLimiter is a sharded senderID -> sliding-window map.
type relayRateLimiter struct {
	shards [rateLimitShards]struct {
		mu sync.Mutex
		m  map[uint32]*relaySourceWindow
	}
}

func newRelayRateLimiter() *relayRateLimiter {
	rl := &relayRateLimiter{}
	for i := range rl.shards {
		rl.shards[i].m = make(map[uint32]*relaySourceWindow)
	}
	return rl
}

// allow reports whether a relay from senderID is within its per-second
// budget, advancing the window as needed.
func (rl *relayRateLimiter) allow(senderID uint32, nowNano int64, maxPerSecond uint32) bool {
	sh := &rl.shards[shardU32(senderID)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	w, ok := sh.m[senderID]
	if !ok || nowNano-w.windowStart >= int64(time.Second) {
		sh.m[senderID] = &relaySourceWindow{windowStart: nowNano, count: 1}
		return true
	}
	if w.count >= maxPerSecond {
		return false
	}
	w.count++
	return true
}

func (rl *relayRateLimiter) sweep(cutoffNano int64) {
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		for id, w := range sh.m {
			if w.windowStart < cutoffNano {
				delete(sh.m, id)
			}
		}
		sh.mu.Unlock()
	}
}
