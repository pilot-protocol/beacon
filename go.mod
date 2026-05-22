module github.com/pilot-protocol/beacon

go 1.25.3

require (
	github.com/TeoSlayer/pilotprotocol v0.0.0
	github.com/coder/websocket v1.8.14
	github.com/pilot-protocol/common v0.0.0
	golang.org/x/net v0.54.0
)

require golang.org/x/sys v0.44.0 // indirect

replace github.com/TeoSlayer/pilotprotocol => ../web4

// Mirror web4's replace directives so transitive deps resolve.
replace github.com/pilot-protocol/app-store => ../app-store

replace github.com/pilot-protocol/trustedagents => ../trustedagents

replace github.com/pilot-protocol/skillinject => ../skillinject

replace github.com/pilot-protocol/webhook => ../webhook

replace github.com/pilot-protocol/eventstream => ../eventstream

replace github.com/pilot-protocol/dataexchange => ../dataexchange

replace github.com/pilot-protocol/updater => ../updater

replace github.com/pilot-protocol/gateway => ../gateway

replace github.com/pilot-protocol/nameserver => ../nameserver

replace github.com/pilot-protocol/policy => ../policy

replace github.com/pilot-protocol/handshake => ../handshake

replace github.com/pilot-protocol/runtime => ../runtime

replace github.com/pilot-protocol/common => ../common

replace github.com/pilot-protocol/rendezvous => ../rendezvous
