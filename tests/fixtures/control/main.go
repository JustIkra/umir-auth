package main

import (
	"fmt"
	"os"

	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "profile" && os.Args[2] == "--request" && os.Args[3] == protocol.ProfileRequestPath {
		if e := protocol.ProfileFromFile(); e != nil {
			fail()
		}
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "request" {
		fail()
	}
	if e := protocol.RequestFromStdin(); e != nil {
		fail()
	}
}
func fail() {
	if _, e := fmt.Fprintln(os.Stderr, "Auth fixture control unavailable"); e != nil {
		os.Exit(1)
	}
	os.Exit(1)
}
