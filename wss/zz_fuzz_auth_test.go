// SPDX-License-Identifier: AGPL-3.0-or-later

package wss_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	cw "github.com/coder/websocket"

	"github.com/pilot-protocol/beacon/wss"
)

// The compat-mode WSS bridge terminates connections from anywhere the
// operator's reverse proxy accepts, and the auth reply is pure
// attacker-controlled JSON. The reply's node_id selects which key
// PubKeyLookup returns, and that key goes to ed25519.Verify — which panics
// on anything that is not exactly PublicKeySize bytes. PubKeyLookup is
// supplied by the embedding process (the registry, in production), so the
// bridge cannot assume its output is well-formed.
//
// Node IDs 1..5 below map to the malformed key shapes; node 9 maps to a
// real key so the well-formed path stays covered.
func fuzzAuthServer(tb testing.TB) (*wss.Server, string) {
	tb.Helper()

	realPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatalf("keygen: %v", err)
	}
	keys := map[uint32]ed25519.PublicKey{
		1: nil,
		2: {},
		3: make([]byte, 1),
		4: make([]byte, ed25519.PublicKeySize-1),
		5: make([]byte, ed25519.PublicKeySize+1),
		9: realPub,
	}

	s, err := wss.New(wss.Config{
		BindAddr:     "127.0.0.1:0",
		AuthTimeout:  2 * time.Second,
		IdleTimeout:  2 * time.Second,
		PubKeyLookup: func(id uint32) (ed25519.PublicKey, bool) { k, ok := keys[id]; return k, ok },
		OnFrame:      func(uint32, []byte) {},
	})
	if err != nil {
		tb.Fatalf("wss.New: %v", err)
	}
	if err := s.Start(); err != nil {
		tb.Fatalf("wss.Start: %v", err)
	}
	tb.Cleanup(func() { _ = s.Close() })
	return s, "ws://" + s.Addr() + "/v1/compat"
}

// FuzzWSSAuthReply drives arbitrary bytes into the post-upgrade auth reply.
// A malformed reply must close the connection with an auth failure, never
// panic the handler.
func FuzzWSSAuthReply(f *testing.F) {
	sig := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))

	add := func(v map[string]interface{}) {
		if b, err := json.Marshal(v); err == nil {
			f.Add(b)
		}
	}
	// One reply per malformed-key node id, plus the well-formed one.
	for _, id := range []int{1, 2, 3, 4, 5, 9, 0, 77} {
		add(map[string]interface{}{
			"type": "auth_reply", "node_id": id,
			"public_key": base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			"sig":        sig,
		})
	}
	// Wrong-length and non-base64 signatures against a malformed-key node.
	for _, n := range []int{0, 1, 63, 65, 128} {
		add(map[string]interface{}{
			"type": "auth_reply", "node_id": 1,
			"sig": base64.StdEncoding.EncodeToString(make([]byte, n)),
		})
	}
	add(map[string]interface{}{"type": "auth_reply", "node_id": 1, "sig": "@@@not base64@@@"})
	add(map[string]interface{}{"type": "wrong_type", "node_id": 1, "sig": sig})
	add(map[string]interface{}{"node_id": 1})
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("null"))
	f.Add([]byte(`{"node_id":99999999999999999999}`))

	srv, url := fuzzAuthServer(f)

	f.Fuzz(func(t *testing.T, reply []byte) {
		if len(reply) > 32*1024 {
			reply = reply[:32*1024]
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		before := srv.Metrics()

		conn, _, err := cw.Dial(ctx, url, &cw.DialOptions{Subprotocols: []string{"pilot.v1"}})
		if err != nil {
			// Server may be shedding connections; not a finding.
			return
		}
		defer conn.Close(cw.StatusNormalClosure, "")

		// Drain the server's challenge, then send the fuzzed reply.
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}
		if err := conn.Write(ctx, cw.MessageText, reply); err != nil {
			return
		}
		// Read the outcome and let the server settle.
		_, _, _ = conn.Read(ctx)

		// Oracle: runAuth is called from an http.Handler, so net/http
		// recovers any panic it raises and the connection just dies — no
		// crash, no test signal. But handleUpgrade only reaches
		// authOK.Add / authFail.Add if runAuth *returned*. So a reply that
		// moves neither counter is one that unwound the handler, which is
		// exactly the panic we are hunting.
		deadline := time.Now().Add(2 * time.Second)
		for {
			after := srv.Metrics()
			if after.AuthOK != before.AuthOK || after.AuthFail != before.AuthFail {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("auth neither succeeded nor failed for reply %q — handler unwound", reply)
			}
			time.Sleep(2 * time.Millisecond)
		}
	})
}
