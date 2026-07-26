// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"net"
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

// relaySourceKey identifies the transport-level origin of a relay
// frame. For a UDP datagram that is the observed source endpoint; for
// a frame handed over by the compat WSS bridge it is the peer id the
// bridge authenticated at connect time. Both are established by the
// transport, not by fields inside the frame the sender wrote.
//
// It is a comparable value type so it can be a map key with no
// per-packet allocation on the relay hot path.
type relaySourceKey struct {
	ip      [16]byte // observed source address in 16-byte form; zero when bridged
	port    uint16   // observed source port; zero when bridged
	node    uint32   // bridge-authenticated peer id; zero for datagrams
	bridged bool
}

// relaySourceForUDP builds the key for a datagram source. It writes the
// IPv4-mapped form by hand rather than calling net.IP.To16, which
// allocates for a 4-byte address.
func relaySourceForUDP(remote *net.UDPAddr) relaySourceKey {
	var k relaySourceKey
	if remote == nil {
		return k
	}
	switch len(remote.IP) {
	case net.IPv4len:
		k.ip[10], k.ip[11] = 0xff, 0xff
		copy(k.ip[12:], remote.IP)
	case net.IPv6len:
		copy(k.ip[:], remote.IP)
	}
	k.port = uint16(remote.Port)
	return k
}

// relaySourceForBridge builds the key for a frame delivered by the
// compat WSS bridge, which has no datagram source of its own.
func relaySourceForBridge(peerID uint32) relaySourceKey {
	return relaySourceKey{node: peerID, bridged: true}
}

func shardRelaySource(k relaySourceKey) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(k.ip); i++ {
		h ^= uint32(k.ip[i])
		h *= 16777619
	}
	h ^= uint32(k.port)
	h *= 16777619
	h ^= k.node
	h *= 16777619
	if k.bridged {
		h ^= 1
		h *= 16777619
	}
	return h & (rateLimitShards - 1)
}

// relayRateLimiter is a sharded relay-source -> sliding-window map.
type relayRateLimiter struct {
	shards [rateLimitShards]struct {
		mu sync.Mutex
		m  map[relaySourceKey]*relaySourceWindow
	}
}

func newRelayRateLimiter() *relayRateLimiter {
	rl := &relayRateLimiter{}
	for i := range rl.shards {
		rl.shards[i].m = make(map[relaySourceKey]*relaySourceWindow)
	}
	return rl
}

// allow reports whether a relay from src is within its per-second
// budget, advancing the window as needed.
func (rl *relayRateLimiter) allow(src relaySourceKey, nowNano int64, maxPerSecond uint32) bool {
	sh := &rl.shards[shardRelaySource(src)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	w, ok := sh.m[src]
	if !ok || nowNano-w.windowStart >= int64(time.Second) {
		sh.m[src] = &relaySourceWindow{windowStart: nowNano, count: 1}
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
