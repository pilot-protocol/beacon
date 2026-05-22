# beacon

Pilot Protocol beacon. The NAT-traversal sidecar that runs alongside
the rendezvous server at the network edge:

- **STUN** — daemons hit it to learn their public `host:port`.
- **Hole punch** — coordinates simultaneous opens for restricted-cone
  NATs (MsgPunchRequest → MsgPunchCommand to both peers).
- **Relay** — fallback path for symmetric NATs that can't punch
  (MsgRelay wrapping; daemon auto-detects on RelayDeliver).
- **Gossip** — sharded peer-state propagation between multiple
  beacons (multi-beacon mode).

## Layout

| File | What it does |
|---|---|
| `server.go` | UDP server: accept/dispatch + shard routing + gossip. |
| `nodes_shard.go` | Per-shard endpoint+last-seen map; SO_REUSEPORT-aware. |
| `reuseport_{linux,other}.go` | Platform-specific SO_REUSEPORT socket opts. |
| `wss/` | WSS (TCP/443) tunnel — fallback for UDP-blocked egress. |
| `cmd/beacon/` | Standalone `pilot-beacon` binary. |

## Build + run

```bash
go build -o pilot-beacon ./cmd/beacon
./pilot-beacon -addr :9001 -beacon-id 1 -peers beacon2:9001,beacon3:9001
```

For GCP MIG deployments, you **must** set `-advertise-addr` to the
public DNAT entrypoint or daemons will see the internal VPC address
and silently fail to reach you.

## Companion services

The beacon is normally deployed on the same VM as the rendezvous
server (`pilot-protocol/rendezvous`). It can also run standalone for
testing or for relay-only edge nodes.

## Releasing

Tag a SemVer version (e.g. `v0.1.0`); web4's daemon-side tests and
the rendezvous repo consume this via `require`. During co-development
consumers use `replace ../beacon`.
