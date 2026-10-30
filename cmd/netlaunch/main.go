package main

import (
	"fmt"
	"netlaunch/internal/app"
	"os"
)

func main() {
	if e := (app.CLI{Out: os.Stdout, Err: os.Stderr}).Run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "NetLaunch:", e)
		os.Exit(1)
	}
}
