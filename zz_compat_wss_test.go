// SPDX-License-Identifier: AGPL-3.0-or-later

package beacon

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/common/crypto"
)

// authChallengeMsg / authReplyMsg / authOKMsg mirror the unexported
// types in the wss server — we duplicate them here so this test can
// drive the WSS bridge without importing the internal daemon client.
type authChallengeMsg struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
}

type authReplyMsg struct {
	Type      string `json:"type"`
	NodeID    uint32 `json:"node_id"`
	PublicKey string `json:"public_key"`
	Sig       string `json:"sig"`
}

type authOKMsg struct {
	Type string `json:"type"`
}

// dialCompatWSS opens a ws:// connection to the bridge at addr and
// completes the Ed25519 challenge as nodeID. Returns the live conn.
func dialCompatWSS(t *testing.T, addr string, id *crypto.Identity, nodeID uint32) *websocket.Conn {
	t.Helper()
	url := "ws://" + addr + "/v1/compat"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		Subprotocols: []string{"pilot.v1"},
	})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}

	// 1. Read challenge.
	msgType, body, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if msgType != websocket.MessageText {
		t.Fatalf("challenge frame type = %v", msgType)
	}
	var ch authChallengeMsg
	if err := json.Unmarshal(body, &ch); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}
	if ch.Type != "auth_challenge" {
		t.Fatalf("challenge type = %q", ch.Type)
	}

	// 2. Sign and reply.
	signed := []byte(fmt.Sprintf("compat_auth:%d:%s", nodeID, ch.Nonce))
	sig := id.Sign(signed)
	reply := authReplyMsg{
		Type:      "auth_reply",
		NodeID:    nodeID,
		PublicKey: crypto.EncodePublicKey(id.PublicKey),
		Sig:       base64.StdEncoding.EncodeToString(sig),
	}
	replyBytes, _ := json.Marshal(reply)
	if err := conn.Write(ctx, websocket.MessageText, replyBytes); err != nil {
		t.Fatalf("write reply: %v", err)
	}

	// 3. Read auth_ok.
	msgType, body, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("read auth_ok: %v", err)
	}
	if msgType != websocket.MessageText {
		t.Fatalf("auth_ok frame type = %v", msgType)
	}
	var ok authOKMsg
	if err := json.Unmarshal(body, &ok); err != nil {
		t.Fatalf("unmarshal auth_ok: %v", err)
	}
	if ok.Type != "auth_ok" {
		t.Fatalf("auth_ok type = %q", ok.Type)
	}
	return conn
}

// TestEnableCompatWSS_HappyPath covers the previously-uncovered
// EnableCompatWSS branch plus the post-attach accessors
// (WSSAddr / WSSIsConnected / WSSMetrics) that all short-circuit to
// "no wss configured" defaults when wssServer is nil.
//
// Also exercises:
//   - relayWorker WSS tier-0 branch (WSS-bound relay path)
//   - dispatchRelay WSS-only destination (peer not in local nodes map)
//   - CloseCompatWSS non-nil branch + post-close idempotency
func TestEnableCompatWSS_HappyPath(t *testing.T) {
	t.Parallel()

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	nodeID := uint32(4242)

	s := New()
	go s.ListenAndServe("127.0.0.1:0")
	<-s.Ready()
	defer s.Close()

	lookup := func(qid uint32) (ed25519.PublicKey, bool) {
		if qid == nodeID {
			return ed25519.PublicKey(id.PublicKey), true
		}
		return nil, false
	}

	if err := s.EnableCompatWSS("127.0.0.1:0", lookup); err != nil {
		t.Fatalf("EnableCompatWSS: %v", err)
	}

	wsAddr := s.WSSAddr()
	if wsAddr == "" {
		t.Fatal("WSSAddr empty after EnableCompatWSS")
	}

	// Double-enable should be rejected.
	if err := s.EnableCompatWSS("127.0.0.1:0", lookup); err == nil {
		t.Error("second EnableCompatWSS should error")
	}

	if s.WSSIsConnected(nodeID) {
		t.Error("WSSIsConnected before dial: want false")
	}
	if m := s.WSSMetrics(); m.ActivePeers != 0 {
		t.Errorf("ActivePeers pre-dial = %d, want 0", m.ActivePeers)
	}

	// Wait briefly for the http.Server goroutine to actually be ready
	// to accept upgrades. The bridge's Start binds the listener but
	// the http.Server.Serve goroutine may not yet have entered Accept.
	// 10s outer budget — public CI runners under -race can take >2s
	// before the goroutine reaches Accept.
	// 30s outer budget — under -race + the expanded daemonwss test set,
	// CI runners have been observed taking 13+ seconds before the
	// http.Server.Serve goroutine reaches Accept. 30s gives margin
	// without making the happy path slow (still ~10ms in practice).
	if !waitUntil(30*time.Second, func() bool {
		_, err := net.DialTimeout("tcp", wsAddr, 1*time.Second)
		return err == nil
	}) {
		t.Fatal("WSS bridge never accepted a TCP dial")
	}

	conn := dialCompatWSS(t, wsAddr, id, nodeID)
	defer conn.Close(websocket.StatusNormalClosure, "test done")

	if !waitUntil(2*time.Second, func() bool { return s.WSSIsConnected(nodeID) }) {
		t.Fatal("WSSIsConnected never became true after dial")
	}

	// Drive the WSS OnFrame path: a 5-byte Discover datagram framed as
	// a binary WS message. handlePacket routes to handleDiscover; the
	// synthetic source IP gets recorded in the nodes map.
	disc := make([]byte, 5)
	disc[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(disc[1:], nodeID)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, disc); err != nil {
		t.Fatalf("ws write discover: %v", err)
	}

	// Now exercise the relayWorker WSS tier-0 branch: send a relay
	// destined for the WSS-connected nodeID over UDP. The dispatch
	// pre-check sees the dest in the WSS table; the worker's Tier-0
	// branch writes a binary frame back to the WSS conn.
	relay := make([]byte, 1+4+4+4)
	relay[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(relay[1:5], 9999) // sender
	binary.BigEndian.PutUint32(relay[5:9], nodeID)
	copy(relay[9:], []byte("PING"))

	udpConn, err := net.DialUDP("udp", nil, beaconUDPAddr(t, s))
	if err != nil {
		t.Fatalf("dial beacon udp: %v", err)
	}
	defer udpConn.Close()
	if _, err := udpConn.Write(relay); err != nil {
		t.Fatalf("write relay udp: %v", err)
	}

	// Read the relayed frame back from the daemon side.
	readCtx, readCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer readCancel()
	msgType, body, err := conn.Read(readCtx)
	if err != nil {
		t.Fatalf("ws read relayed frame: %v", err)
	}
	if msgType != websocket.MessageBinary {
		t.Fatalf("relayed frame type = %v", msgType)
	}
	if len(body) < 1 || body[0] != protocol.BeaconMsgRelayDeliver {
		t.Fatalf("relayed frame[0] = 0x%02x, want RelayDeliver", body[0])
	}
	if string(body[5:]) != "PING" {
		t.Errorf("relayed payload = %q, want PING", body[5:])
	}

	if got := s.RelayForwarded(); got == 0 {
		t.Error("RelayForwarded = 0 after WSS relay; want >= 1")
	}

	m := s.WSSMetrics()
	if m.ActivePeers != 1 {
		t.Errorf("ActivePeers = %d, want 1", m.ActivePeers)
	}
	if m.FramesOut == 0 {
		t.Error("FramesOut = 0; want >= 1")
	}

	// Close the WSS bridge — covers the non-nil branch.
	if err := s.CloseCompatWSS(); err != nil {
		t.Errorf("CloseCompatWSS: %v", err)
	}
	if err := s.CloseCompatWSS(); err != nil {
		t.Errorf("CloseCompatWSS (second): %v", err)
	}
	if s.WSSAddr() != "" {
		t.Error("WSSAddr after close should be empty")
	}
}
