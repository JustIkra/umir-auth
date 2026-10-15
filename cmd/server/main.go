package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/JustIkra/umir-auth/bootstrap"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	path := os.Getenv("UMIR_AUTH_CONFIG_FILE")
	if path == "" {
		path = "/etc/umir-auth/config.json"
	}
	if e := bootstrap.Run(ctx, path); e != nil {
		if _, e = fmt.Fprintln(os.Stderr, e); e != nil {
			os.Exit(1)
		}
		os.Exit(1)
	}
}
