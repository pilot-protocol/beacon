# beacon

[![ci](https://github.com/pilot-protocol/beacon/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/beacon/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/beacon/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/beacon)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

The Pilot Protocol beacon. The NAT-traversal sidecar that runs alongside the rendezvous server at the network edge:

- **STUN** — daemons hit it to learn their public `host:port`.
- **Hole punch** — coordinates simultaneous opens for restricted-cone NATs (`MsgPunchRequest` → `MsgPunchCommand` to both peers).
- **Relay** — fallback path for symmetric NATs that can't punch (`MsgRelay` wrapping; daemons auto-detect on `RelayDeliver`).
- **Gossip** — sharded peer-state propagation between multiple beacons in multi-beacon deployments.

> **This repository is published for source-code transparency and auditability.** It is **not** a self-hosting guide. The canonical Pilot Protocol beacon is operated by Vulture Labs at `34.71.57.205:9001` (alongside the rendezvous at `34.71.57.205:9000`); production daemons connect there by default. If you want to read the code that produced the binary your daemon's relay path is routing through, you're in the right place.

## Architecture

The beacon runs a single UDP listener (default port 9001) plus an optional WSS TCP/443 fallback for UDP-blocked egress. It is a fixed-public-endpoint service: daemons send it `MsgRegister`, `MsgPunchRequest`, `MsgRelay`, and `MsgStun` packets, and the beacon dispatches based on a sharded in-memory map of node ID → last-seen UDP endpoint.

State is fully ephemeral — the beacon is restart-tolerant because daemons re-register on a short keepalive interval. In multi-beacon deployments, peer-state is propagated via gossip across the configured peers.

`SO_REUSEPORT` is used on Linux to scale across multiple accept goroutines on the same UDP port.

## Layout

| File | What it does |
|---|---|
| `server.go` | UDP server: accept/dispatch + shard routing + gossip. |
| `nodes_shard.go` | Per-shard endpoint+last-seen map; `SO_REUSEPORT`-aware. |
| `reuseport_{linux,other}.go` | Platform-specific `SO_REUSEPORT` socket opts. |
| `wss/` | WSS (TCP/443) tunnel — fallback for UDP-blocked egress. |
| `cmd/beacon/` | Standalone binary entrypoint. |

## Build locally

If you want to compile the source locally — for example to read the exact binary that produced your daemon's relay traffic, or to step through it under a debugger:

```bash
go build ./cmd/beacon
```

The build is hermetic Go with no cgo; any Go toolchain at the version pinned in `go.mod` will reproduce the binary.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
