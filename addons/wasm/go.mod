module github.com/Lu4nScr1pt1ng/okena/addons/wasm

go 1.25.0

require (
	github.com/Lu4nScr1pt1ng/okena/sdk/go v0.0.0
	github.com/tetratelabs/wazero v1.12.0
)

require golang.org/x/sys v0.44.0 // indirect

replace github.com/Lu4nScr1pt1ng/okena/sdk/go => ../../sdk/go
