// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeRegistry is a one-shot TCP server that speaks the length-prefix
// JSON framing the beacon's registryDiscover uses. It captures the
// first message (expected: beacon_register) and answers; then captures
// the second (beacon_list) and answers with a configurable peer list.
type fakeRegistry struct {
	t         *testing.T
	ln        net.Listener
	mu        sync.Mutex
	registers []map[string]interface{}
	beacons   []map[string]interface{}
	doneCh    chan struct{}
	wg        sync.WaitGroup
}

func newFakeRegistry(t *testing.T, beacons []map[string]interface{}) *fakeRegistry {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &fakeRegistry{
		t:       t,
		ln:      ln,
		beacons: beacons,
		doneCh:  make(chan struct{}),
	}
	r.wg.Add(1)
	go r.acceptLoop()
	return r
}

func (r *fakeRegistry) addr() string { return r.ln.Addr().String() }

func (r *fakeRegistry) close() {
	close(r.doneCh)
	_ = r.ln.Close()
	r.wg.Wait()
}

func (r *fakeRegistry) acceptLoop() {
	defer r.wg.Done()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.serve(conn)
	}
}

func (r *fakeRegistry) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Read frame 1 → register
	reg, err := readFrame(conn)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.registers = append(r.registers, reg)
	r.mu.Unlock()
	if err := writeFrame(conn, map[string]interface{}{"ok": true}); err != nil {
		return
	}

	// Read frame 2 → list
	if _, err := readFrame(conn); err != nil {
		return
	}
	resp := map[string]interface{}{"beacons": r.beacons}
	_ = writeFrame(conn, resp)
}

func (r *fakeRegistry) registeredCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.registers)
}

func (r *fakeRegistry) lastRegister() map[string]interface{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.registers) == 0 {
		return nil
	}
	return r.registers[len(r.registers)-1]
}

func readFrame(conn net.Conn) (map[string]interface{}, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func writeFrame(conn net.Conn, m map[string]interface{}) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = conn.Write(body)
	return err
}

// TestRegistryDiscover_FullPath drives registryDiscover end-to-end:
// the beacon sends beacon_register + beacon_list to a fake registry,
// receives a peer list including a self-entry (skipped) and one peer
// (kept), and updates s.peers.
func TestRegistryDiscover_FullPath(t *testing.T) {
	t.Parallel()

	const myID = uint32(1)
	reg := newFakeRegistry(t, []map[string]interface{}{
		{"id": float64(myID), "addr": "127.0.0.1:9999"}, // self — should be skipped
		{"id": float64(2), "addr": "127.0.0.1:9000"},    // peer — kept
		{"id": float64(3), "addr": "not a valid addr"},  // bad — skipped
		{"id": float64(4)},                              // empty addr — skipped
	})
	defer reg.close()

	s := NewWithPeers(myID, nil)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	// Set the registry AFTER Ready so the auto-loop's immediate first
	// tick races against our direct call. We assert >=1 to tolerate
	// that race — the goal is coverage of the full happy path, not
	// strict call-count semantics.
	s.SetRegistry(reg.addr())
	s.SetAdvertiseAddr("203.0.113.7:9001")
	s.SetRegistryAdminToken("hunter2")

	// Call registryDiscover directly for determinism.
	s.registryDiscover()

	if !waitUntil(2*time.Second, func() bool { return reg.registeredCount() >= 1 }) {
		t.Fatalf("registry got %d register calls, want >= 1", reg.registeredCount())
	}
	last := reg.lastRegister()
	if last["type"] != "beacon_register" {
		t.Errorf("register type = %v, want beacon_register", last["type"])
	}
	if last["addr"] != "203.0.113.7:9001" {
		t.Errorf("register addr = %v, want advertised", last["addr"])
	}
	if last["admin_token"] != "hunter2" {
		t.Errorf("admin_token = %v, want hunter2", last["admin_token"])
	}

	// peers should be 1 (only id=2 made it through filtering).
	s.peerMu.RLock()
	gotPeers := len(s.peers)
	s.peerMu.RUnlock()
	if gotPeers != 1 {
		t.Errorf("peers count = %d, want 1 (self + bad ones filtered)", gotPeers)
	}
}

// TestRegistryDiscover_NoRegistryConfigured returns early without
// dialing — the noop path that today shows as the only branch hit
// at all (8.6%).
func TestRegistryDiscover_NoRegistryConfigured(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(7, nil)
	// No SetRegistry — should be a quiet no-op.
	s.registryDiscover()
}

// TestRegistryDiscover_StandaloneBeaconIDZero returns early because
// beaconID==0 means "standalone, don't register".
func TestRegistryDiscover_StandaloneBeaconIDZero(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(0, nil)
	s.SetRegistry("127.0.0.1:1")
	s.registryDiscover()
}

// TestRegistryDiscover_DialFailure exercises the dial-error branch
// — the registry address does not accept connections.
func TestRegistryDiscover_DialFailure(t *testing.T) {
	t.Parallel()
	s := NewWithPeers(5, nil)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	// Pick a port that is almost certainly closed.
	s.SetRegistry("127.0.0.1:1")
	s.registryDiscover()
	// No assertion — we just want the error path to execute without panic.
}

// TestRegistryDiscover_AutoDetectAddr exercises the no-advertise
// branch where the beacon derives the registration addr from its own
// listen + TCP local addr.
func TestRegistryDiscover_AutoDetectAddr(t *testing.T) {
	t.Parallel()

	reg := newFakeRegistry(t, nil) // no peers
	defer reg.close()

	s := NewWithPeers(11, nil)
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()
	s.SetRegistry(reg.addr())
	// No SetAdvertiseAddr — exercise the host-from-TCP-local-addr branch.

	s.registryDiscover()

	if !waitUntil(2*time.Second, func() bool { return reg.lastRegister() != nil }) {
		t.Fatal("registry never received a register call")
	}
	last := reg.lastRegister()
	addr, _ := last["addr"].(string)
	if addr == "" {
		t.Fatal("auto-detected addr was empty")
	}
	// We just check it parses as host:port — the actual IP depends on
	// the loopback interface.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		t.Errorf("auto-detected addr %q: SplitHostPort: %v", addr, err)
	}
}
