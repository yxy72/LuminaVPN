package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"netlaunch/internal/app"
	"netlaunch/internal/desktopbridge"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "desktop" {
		if err := desktopbridge.Run(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "NetLaunch: desktop bridge unavailable")
			os.Exit(1)
		}
		return
	}
	ctx := context.Background()
	cancel := func() {}
	if len(os.Args) > 1 && (os.Args[1] == "up" || os.Args[1] == "down") {
		ctx, cancel = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
	e := (app.CLI{Out: os.Stdout, Err: os.Stderr}).RunContext(ctx, os.Args[1:])
	cancel()
	if e != nil {
		fmt.Fprintln(os.Stderr, "NetLaunch:", e)
		os.Exit(1)
	}
}
