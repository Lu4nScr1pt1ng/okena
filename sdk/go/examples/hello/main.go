// An addon in Go: lets requests go on with x-checked: yes, answers /blocked
// itself, and takes x-debug away.
//
//	go build -o hello ./examples/hello
//	addon hello { run /path/to/hello }
package main

import (
	"log"
	"strings"

	addon "github.com/Lu4nScr1pt1ng/okena/sdk/go"
)

func main() {
	log.Fatal(addon.Run(func(r *addon.Request, a *addon.Answer) {
		switch {
		case strings.HasSuffix(r.Path(), "/blocked"):
			a.Respond(403)
			a.Add("content-type", "text/plain")
			a.Body([]byte("blocked by the addon\n"))
		case strings.HasSuffix(r.Path(), "/pass"):
		default:
			a.Set("x-checked", "yes")
			a.Remove("x-debug")
		}
	}, addon.Options{}))
}
