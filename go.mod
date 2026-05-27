module github.com/pilot-protocol/beacon

go 1.25.10

require (
	github.com/TeoSlayer/pilotprotocol v0.0.0
	github.com/coder/websocket v1.8.14
	github.com/pilot-protocol/common v0.1.0
	golang.org/x/net v0.55.0
)

require golang.org/x/sys v0.45.0 // indirect

replace github.com/TeoSlayer/pilotprotocol => ../web4
