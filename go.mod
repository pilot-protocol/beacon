module github.com/pilot-protocol/beacon

go 1.25.3

require (
	github.com/TeoSlayer/pilotprotocol v0.0.0
	github.com/coder/websocket v1.8.14
	github.com/pilot-protocol/common v0.1.0
	golang.org/x/net v0.54.0
)

require golang.org/x/sys v0.44.0 // indirect

replace github.com/TeoSlayer/pilotprotocol => ../web4
