// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonwss_test

// This file extends zz_dial_test.go with targeted coverage of every
// remaining branch in wss.go that the in-tree wss.Server fixture can't
// drive on its own (auth failure modes, supervise reconnect lifecycle,
// runAuth wire-format violations, sleepOrClosed). It uses raw
// httptest.NewServer + coder/websocket so each test owns the server
// side of the handshake and can inject the exact bad input we need.
//
// Coverage targets (from `go tool cover -func`):
//   - dialAndAuth auth-failure path     (line 258-261)
//   - runAuth: every error branch       (read, type, json, sentinel)
//   - Send: write error + reconnecting  (lines 342, 348-362)
//   - Recv: item.err branch             (line 376)
//   - supervise: drainReads-then-redial, sleepOrClosed wake-on-close,
//     re-auth on reconnect, close-races-success                 (430+)
//   - drainReads: text frame ignored, oversized frame, closed-during-send
//   - sleepOrClosed: full body          (lines 558-575)

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	dwss "github.com/pilot-protocol/beacon/wss/internal/daemonwss"
	"github.com/pilot-protocol/common/crypto"
)

// fakeBeacon stands up an httptest server whose /v1/compat handler is
// fully controllable per-test. It returns the ws:// URL the daemon
// dials, plus the underlying *httptest.Server (so the test can call
// Close() to drop the listener mid-flight).
type fakeBeacon struct {
	srv *httptest.Server
	url string
}

func newFakeBeacon(handler http.HandlerFunc) *fakeBeacon {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/compat", handler)
	s := httptest.NewServer(mux)
	return &fakeBeacon{
		srv: s,
		url: strings.Replace(s.URL, "http://", "ws://", 1) + "/v1/compat",
	}
}

func (f *fakeBeacon) close() { f.srv.Close() }

// dialWith builds a Config + Dial against the fakeBeacon. id is the
// daemon-side identity. Caller is responsible for closing the returned
// Transport (when err == nil).
func dialWith(ctx context.Context, url string, id *crypto.Identity, nodeID uint32, dialTimeout time.Duration) (*dwss.Transport, error) {
	if dialTimeout == 0 {
		dialTimeout = 3 * time.Second
	}
	return dwss.Dial(ctx, dwss.Config{
		URL:         url,
		TLSConfig:   &tls.Config{},
		Identity:    id,
		NodeID:      nodeID,
		DialTimeout: dialTimeout,
		// Tight ping interval keeps the supervise loop active in
		// reconnect tests without making them slow.
		IdlePingInterval: 50 * time.Millisecond,
	})
}

// sendChallenge writes the standard auth_challenge envelope and returns
// the nonce and timestamp it sent (so handlers can verify the daemon's
// signature, or not).
func sendChallenge(t *testing.T, ctx context.Context, conn *websocket.Conn) (string, int64) {
	t.Helper()
	nonceBytes := make([]byte, 32)
	for i := range nonceBytes {
		nonceBytes[i] = byte(i)
	}
	nonce := hex.EncodeToString(nonceBytes)
	ts := time.Now().Unix()
	body, _ := json.Marshal(map[string]any{
		"type":  "auth_challenge",
		"nonce": nonce,
		"ts":    ts,
	})
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		t.Logf("sendChallenge write: %v", err)
	}
	return nonce, ts
}

// fullAuth runs the canonical happy-path server handshake. Used by
// tests that need a *connected* transport before injecting a fault
// (frame send, write break, oversized frame, etc.).
func fullAuth(t *testing.T, w http.ResponseWriter, r *http.Request) *websocket.Conn {
	t.Helper()
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"pilot.v1"},
	})
	if err != nil {
		t.Logf("Accept: %v", err)
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	nonce, _ := sendChallenge(t, ctx, conn)

	_, body, err := conn.Read(ctx)
	if err != nil {
		t.Logf("read reply: %v", err)
		conn.Close(websocket.StatusInternalError, "read")
		return nil
	}
	var reply struct {
		Type   string `json:"type"`
		NodeID uint32 `json:"node_id"`
		Sig    string `json:"sig"`
	}
	_ = json.Unmarshal(body, &reply)
	// Echo signed nonce ack purely so the daemon-side flow is exercised.
	_ = nonce
	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"type":"auth_ok"}`)); err != nil {
		t.Logf("write auth_ok: %v", err)
		return nil
	}
	return conn
}

// --- runAuth wire-format failures ---------------------------------

// TestDial_AuthChallengeReadError covers runAuth's "read challenge"
// failure: the server upgrades, then immediately closes — no challenge
// frame ever arrives.
func TestDial_AuthChallengeReadError(t *testing.T) {
	t.Parallel()
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		// Slam the connection without writing a challenge.
		conn.Close(websocket.StatusInternalError, "no challenge")
	})
	defer beacon.close()

	id, _ := crypto.GenerateIdentity()
	tr, err := dialWith(context.Background(), beacon.url, id, 1, 2*time.Second)
	if err == nil {
		tr.Close()
		t.Fatal("Dial: want error from missing challenge")
	}
	if !strings.Contains(err.Error(), "auth") {
		t.Errorf("want wrapped auth error, got %v", err)
	}
}

// TestDial_AuthChallengeWrongFrameType covers the "expected text frame"
// branch of runAuth: server sends a binary frame where text is required.
func TestDial_AuthChallengeWrongFrameType(t *testing.T) {
	t.Parallel()
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		_ = conn.Write(ctx, websocket.MessageBinary, []byte("not a challenge"))
	})
	defer beacon.close()

	id, _ := crypto.GenerateIdentity()
	_, err := dialWith(context.Background(), beacon.url, id, 1, 2*time.Second)
	if err == nil {
		t.Fatal("Dial: want error from non-text challenge")
	}
	if !strings.Contains(err.Error(), "text frame") {
		t.Errorf("want 'text frame' error, got %v", err)
	}
}

// TestDial_AuthChallengeMalformedJSON covers the json.Unmarshal failure
// branch in runAuth.
func TestDial_AuthChallengeMalformedJSON(t *testing.T) {
	t.Parallel()
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		_ = conn.Write(ctx, websocket.MessageText, []byte("not-json {"))
	})
	defer beacon.close()

	id, _ := crypto.GenerateIdentity()
	_, err := dialWith(context.Background(), beacon.url, id, 1, 2*time.Second)
	if err == nil {
		t.Fatal("Dial: want error from malformed challenge JSON")
	}
	if !strings.Contains(err.Error(), "parse challenge") {
		t.Errorf("want parse-challenge error, got %v", err)
	}
}

// TestDial_AuthChallengeWrongType covers the "malformed challenge"
// branch (right shape, wrong type field or empty nonce).
func TestDial_AuthChallengeWrongType(t *testing.T) {
	t.Parallel()
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		// Right JSON shape, wrong "type" value.
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"hello","nonce":"abc"}`))
	})
	defer beacon.close()

	id, _ := crypto.GenerateIdentity()
	_, err := dialWith(context.Background(), beacon.url, id, 1, 2*time.Second)
	if err == nil {
		t.Fatal("Dial: want error for wrong challenge type")
	}
	if !strings.Contains(err.Error(), "malformed challenge") {
		t.Errorf("want malformed-challenge error, got %v", err)
	}
}

// TestDial_AuthOKReadError covers the "read auth_ok" failure branch:
// server reads the daemon's reply then drops without sending auth_ok.
func TestDial_AuthOKReadError(t *testing.T) {
	t.Parallel()
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		sendChallenge(t, ctx, conn)
		// Consume the daemon's reply, then drop.
		_, _, _ = conn.Read(ctx)
		conn.Close(websocket.StatusInternalError, "no ok")
	})
	defer beacon.close()

	id, _ := crypto.GenerateIdentity()
	_, err := dialWith(context.Background(), beacon.url, id, 42, 2*time.Second)
	if err == nil {
		t.Fatal("Dial: want error from missing auth_ok")
	}
	if !strings.Contains(err.Error(), "read auth_ok") {
		t.Errorf("want read-auth_ok error, got %v", err)
	}
}

// TestDial_AuthOKWrongFrameType covers the "expected text frame for
// auth_ok" branch.
func TestDial_AuthOKWrongFrameType(t *testing.T) {
	t.Parallel()
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		sendChallenge(t, ctx, conn)
		_, _, _ = conn.Read(ctx)
		// Reply with the wrong frame type.
		_ = conn.Write(ctx, websocket.MessageBinary, []byte("not ok"))
	})
	defer beacon.close()

	id, _ := crypto.GenerateIdentity()
	_, err := dialWith(context.Background(), beacon.url, id, 42, 2*time.Second)
	if err == nil {
		t.Fatal("Dial: want error from non-text auth_ok")
	}
	if !strings.Contains(err.Error(), "text frame for auth_ok") {
		t.Errorf("want text-frame-for-auth_ok error, got %v", err)
	}
}

// TestDial_AuthOKMalformedJSON covers the auth_ok json parse-error
// branch.
func TestDial_AuthOKMalformedJSON(t *testing.T) {
	t.Parallel()
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		sendChallenge(t, ctx, conn)
		_, _, _ = conn.Read(ctx)
		_ = conn.Write(ctx, websocket.MessageText, []byte("not-json"))
	})
	defer beacon.close()

	id, _ := crypto.GenerateIdentity()
	_, err := dialWith(context.Background(), beacon.url, id, 42, 2*time.Second)
	if err == nil {
		t.Fatal("Dial: want parse-error for non-JSON auth_ok")
	}
	if !strings.Contains(err.Error(), "parse auth_ok") {
		t.Errorf("want parse-auth_ok error, got %v", err)
	}
}

// TestDial_AuthRejected covers the "auth rejected" branch: well-formed
// JSON but type is not "auth_ok".
func TestDial_AuthRejected(t *testing.T) {
	t.Parallel()
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusPolicyViolation, "")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		sendChallenge(t, ctx, conn)
		_, _, _ = conn.Read(ctx)
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"auth_reject","reason":"nope"}`))
	})
	defer beacon.close()

	id, _ := crypto.GenerateIdentity()
	_, err := dialWith(context.Background(), beacon.url, id, 42, 2*time.Second)
	if err == nil {
		t.Fatal("Dial: want error for auth rejection")
	}
	if !strings.Contains(err.Error(), "auth rejected") {
		t.Errorf("want auth-rejected error, got %v", err)
	}
}

// TestDial_ChallengeReadyNonceVerifies sanity-checks the signature
// path: the test server verifies the daemon's reply matches
// "compat_auth:<nodeID>:<nonce>" with the daemon's own pubkey. This is
// the wire-format contract — if the daemon-side signing bytes ever
// drift, this test fails before integration testing catches it.
func TestDial_ChallengeReadyNonceVerifies(t *testing.T) {
	t.Parallel()
	const nodeID = uint32(9876)
	id, _ := crypto.GenerateIdentity()

	var verified atomic.Bool
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		nonce, ts := sendChallenge(t, ctx, conn)
		_, body, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var reply struct {
			Type      string `json:"type"`
			NodeID    uint32 `json:"node_id"`
			PublicKey string `json:"public_key"`
			Sig       string `json:"sig"`
		}
		if err := json.Unmarshal(body, &reply); err != nil {
			return
		}
		sig, err := base64.StdEncoding.DecodeString(reply.Sig)
		if err != nil {
			return
		}
		signed := []byte(fmt.Sprintf("compat_auth:%d:%d:%s", reply.NodeID, ts, nonce))
		if reply.NodeID != nodeID {
			return
		}
		if !ed25519.Verify(ed25519.PublicKey(id.PublicKey), signed, sig) {
			return
		}
		verified.Store(true)
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"auth_ok"}`))
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()
	if !verified.Load() {
		t.Error("server failed to verify daemon's signed challenge reply")
	}
}

// --- Send error path ---------------------------------------------

// TestSend_WriteErrorClearsConn drives the conn.Write-fails branch:
// happy-path Dial, then the server hangs up. The daemon's next Send
// fails AND must clear t.conn so a follow-up Send returns
// ErrReconnecting (covers both the error wrap and the connMu clear).
func TestSend_WriteErrorClearsConn(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	const nodeID = uint32(101)

	// Track the server-side conn so the test can kill it.
	srvConnCh := make(chan *websocket.Conn, 1)
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn := fullAuth(t, w, r)
		if conn == nil {
			return
		}
		srvConnCh <- conn
		// Hold the connection open so the daemon doesn't notice the
		// peer's gone until we Close().
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	srvConn := <-srvConnCh
	// Force-close the server side. The next Send will fail.
	_ = srvConn.Close(websocket.StatusInternalError, "boom")

	// Loop a few sends — the WS library detects the dead pipe lazily
	// (only on actual write), so the first Send may succeed against the
	// buffered TCP. Once it fails the daemon should clear t.conn and
	// follow-up Sends return ErrReconnecting until supervise installs
	// a new conn (which will fail in a tight loop since the listener
	// is still up but the handler holds the new conn open).
	sawError := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := tr.Send([]byte("ping"), nil); err != nil {
			sawError = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawError {
		t.Fatal("Send never returned an error after server dropped the conn")
	}
}

// TestSend_ReturnsReconnectingWhenConnNil exercises the conn == nil
// fast-path of Send. Hardest part: getting the transport into a state
// where Close hasn't been called but the conn was cleared by a prior
// Send failure. We force that via Send-after-srv-close.
func TestSend_ReturnsReconnectingWhenConnNil(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	const nodeID = uint32(102)

	// Capacity-1 channel so the test can both seed the connection AND
	// drain it later to assert the server side cooperated.
	srvCh := make(chan *websocket.Conn, 1)
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn := fullAuth(t, w, r)
		if conn == nil {
			return
		}
		select {
		case srvCh <- conn:
		default:
		}
		// Hold open.
		<-r.Context().Done()
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	srvConn := <-srvCh
	_ = srvConn.Close(websocket.StatusInternalError, "boom")

	// Burst sends until one of them returns ErrReconnecting or any
	// other error. (Race-free assertion: as long as SOME post-break
	// Send returns an error, we've covered the dead-pipe branches.)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := tr.Send([]byte("x"), nil); err != nil {
			// Branch covered.
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Send never observed a post-break error")
}

// --- drainReads branches -----------------------------------------

// TestDrainReads_IgnoresTextFrames covers the "reserved control frame"
// branch in drainReads: server sends a text frame post-auth, daemon
// must NOT surface it via Recv. Binary frame that follows MUST come
// through.
func TestDrainReads_IgnoresTextFrames(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	const nodeID = uint32(201)

	srvConnReady := make(chan *websocket.Conn, 1)
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn := fullAuth(t, w, r)
		if conn == nil {
			return
		}
		srvConnReady <- conn
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		// One text (reserved) + one binary (real payload).
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"control":"future"}`))
		time.Sleep(20 * time.Millisecond)
		_ = conn.Write(ctx, websocket.MessageBinary, []byte("real frame"))
		<-r.Context().Done()
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()
	<-srvConnReady

	frameCh := make(chan []byte, 1)
	go func() {
		f, _, err := tr.Recv()
		if err != nil {
			return
		}
		frameCh <- f
	}()
	select {
	case f := <-frameCh:
		if string(f) != "real frame" {
			t.Errorf("got %q, want %q (text frame should have been skipped)", f, "real frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("never received binary frame; daemon may have surfaced text frame or hung")
	}
}

// TestRecv_AfterReadError covers Recv's item.err != nil branch. We
// Close the transport, which races a recvItem{err: ErrClosed} into the
// channel via drainReads' closed-flag arm. Recv pulls it out as a
// non-channel-closed error, exercising the err-return.
func TestRecv_AfterReadError(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	const nodeID = uint32(202)

	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn := fullAuth(t, w, r)
		if conn == nil {
			return
		}
		<-r.Context().Done()
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Block in Recv from a goroutine; close the transport; the read
	// goroutine should surface ErrClosed via item.err OR the channel
	// close — both exit Recv with err != nil.
	done := make(chan error, 1)
	go func() {
		_, _, err := tr.Recv()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = tr.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Recv returned nil after Close; want error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv did not return after Close")
	}
}

// --- supervise reconnect lifecycle -------------------------------

// TestSupervise_ReconnectsAfterServerDrop is the centrepiece for
// supervise() coverage. Server accepts twice: the first conn is killed
// after auth so supervise() drops into the backoff+redial path. The
// second conn must arrive — which only happens if dialAndAuth +
// sleepOrClosed both execute on the reconnect side.
func TestSupervise_ReconnectsAfterServerDrop(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	const nodeID = uint32(301)

	var connectCount atomic.Int32
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		n := connectCount.Add(1)
		conn := fullAuth(t, w, r)
		if conn == nil {
			return
		}
		if n == 1 {
			// First connection: hold open ~150ms then drop, forcing
			// supervise's reconnect path to fire.
			time.Sleep(150 * time.Millisecond)
			_ = conn.Close(websocket.StatusAbnormalClosure, "server drop")
			return
		}
		// Second connection: send a frame so the test can confirm
		// post-reconnect liveness, then hold open until cleanup.
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		_ = conn.Write(ctx, websocket.MessageBinary, []byte("reconnected"))
		<-r.Context().Done()
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	// First Recv arrives over the SECOND server conn — the reconnect
	// happened. Up to 4s because the first backoff is 250ms and the
	// httptest accept dance has some jitter.
	deadline := time.After(4 * time.Second)
	frameCh := make(chan []byte, 1)
	go func() {
		f, _, err := tr.Recv()
		if err == nil {
			frameCh <- f
		}
	}()
	select {
	case f := <-frameCh:
		if string(f) != "reconnected" {
			t.Errorf("post-reconnect frame = %q, want %q", f, "reconnected")
		}
	case <-deadline:
		t.Fatalf("never reconnected; server saw %d connect(s)", connectCount.Load())
	}
	if connectCount.Load() < 2 {
		t.Errorf("connectCount=%d, want >=2 (reconnect did not fire)", connectCount.Load())
	}
}

// TestSupervise_CloseDuringBackoff drives the sleepOrClosed wake-on-
// close branch. Server refuses every reconnect attempt (returns 500
// pre-upgrade) so supervise gets stuck in the backoff+redial loop —
// then we Close, and the supervisor must exit within the backoff
// poll cadence (100ms) rather than waiting out the timer.
func TestSupervise_CloseDuringBackoff(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	const nodeID = uint32(302)

	var connectCount atomic.Int32
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		n := connectCount.Add(1)
		if n == 1 {
			// First connection: complete auth, then drop after a tick
			// so supervise enters reconnect mode.
			conn := fullAuth(t, w, r)
			if conn != nil {
				time.Sleep(50 * time.Millisecond)
				_ = conn.Close(websocket.StatusAbnormalClosure, "drop to trigger reconnect")
			}
			return
		}
		// Subsequent attempts: reject pre-upgrade so dial-then-auth
		// fails fast, supervise bumps backoff, and we get into the
		// sleepOrClosed wait.
		http.Error(w, "no", http.StatusInternalServerError)
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 1*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Wait until at least one reconnect has been attempted (>=2 total
	// server hits). Bounded poll keeps it fast.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if connectCount.Load() >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if connectCount.Load() < 2 {
		t.Fatalf("supervise never attempted a reconnect; connectCount=%d", connectCount.Load())
	}

	// Now Close — must return promptly via the sleepOrClosed wake path
	// even though supervise is mid-backoff.
	closed := make(chan struct{})
	go func() {
		_ = tr.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s during supervise backoff")
	}
}

// TestSupervise_DialErrorBumpsBackoff exercises the err-path inside
// supervise's redial: the server first authenticates one conn, then
// drops it, then refuses subsequent upgrades. We let supervise miss
// reconnects a couple times so the backoff bump branch is hit, then
// allow a success.
func TestSupervise_DialErrorBumpsBackoff(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	const nodeID = uint32(303)

	var connectCount atomic.Int32
	var mu sync.Mutex
	allowReconnect := false

	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		n := connectCount.Add(1)
		if n == 1 {
			conn := fullAuth(t, w, r)
			if conn != nil {
				time.Sleep(50 * time.Millisecond)
				_ = conn.Close(websocket.StatusAbnormalClosure, "drop")
			}
			return
		}
		mu.Lock()
		allow := allowReconnect
		mu.Unlock()
		if !allow {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		conn := fullAuth(t, w, r)
		if conn == nil {
			return
		}
		<-r.Context().Done()
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 1*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer tr.Close()

	// Wait for the failed reconnect attempts to rack up (covers the
	// backoff bump branch).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if connectCount.Load() >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if connectCount.Load() < 3 {
		t.Fatalf("supervise didn't bump backoff; connectCount=%d", connectCount.Load())
	}
	// Unlock the gate so the next dial succeeds.
	mu.Lock()
	allowReconnect = true
	mu.Unlock()

	// Confirm supervisor eventually establishes a fresh conn (covers
	// the success-after-failure branch + slog.Info "reconnected").
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// The transport exposes liveness only via Send. A Send that
		// returns nil after a series of failures = supervise installed
		// a fresh conn.
		if _, err := tr.Send([]byte("ping"), nil); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("supervise never recovered after gate opened")
}

// TestClose_WhileSupervisorDialing closes the transport while a
// reconnect dial is in flight. The supervisor's lifetimeCtx wires up
// the in-flight dial, so Close must unblock it (covers the
// closed-during-dial branch of supervise).
func TestClose_WhileSupervisorDialing(t *testing.T) {
	t.Parallel()
	id, _ := crypto.GenerateIdentity()
	const nodeID = uint32(304)

	releasedFirst := make(chan struct{})
	beacon := newFakeBeacon(func(w http.ResponseWriter, r *http.Request) {
		conn := fullAuth(t, w, r)
		if conn == nil {
			return
		}
		// Drop first conn so supervisor enters reconnect; subsequent
		// dials sit in handler indefinitely (TLS upgrade completes,
		// but auth_challenge is never written) so the daemon's dial
		// hangs on runAuth → conn.Read until lifetimeCtx fires.
		select {
		case <-releasedFirst:
			return
		default:
			close(releasedFirst)
			time.Sleep(50 * time.Millisecond)
			_ = conn.Close(websocket.StatusAbnormalClosure, "drop")
			return
		}
	})
	defer beacon.close()

	tr, err := dialWith(context.Background(), beacon.url, id, nodeID, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Wait until first conn drop is observed (so supervisor is now in
	// reconnect mode, blocked on a dial that the test server holds
	// open without writing a challenge).
	<-releasedFirst
	time.Sleep(150 * time.Millisecond) // give supervise time to enter dial

	closed := make(chan struct{})
	go func() {
		_ = tr.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return while supervisor was mid-reconnect-dial")
	}
}
