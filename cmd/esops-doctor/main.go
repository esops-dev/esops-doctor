package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/esops-dev/esops-doctor/internal/cli"
	"github.com/esops-dev/esops-doctor/internal/exit"
)

func main() {
	os.Exit(run())
}

// run is split out so deferred cleanup (signal.Stop, cancel) actually
// fires — os.Exit skips deferred funcs.
func run() int {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Track which signal (if any) cancelled the context, so the exit code
	// can follow the Unix convention of 128+sig: SIGINT → 130, SIGTERM →
	// 143. signal.NotifyContext alone collapses both into context.Canceled
	// and loses that information.
	var sig atomic.Pointer[os.Signal]
	go func() {
		select {
		case s := <-sigCh:
			sig.Store(&s)
			cancel()
		case <-ctx.Done():
		}
	}()

	err := cli.Run(ctx, os.Args)

	if err != nil && !exit.IsSilent(err) {
		fmt.Fprintln(os.Stderr, err)
	}

	if s := sig.Load(); s != nil {
		return exit.SignalCode(*s)
	}
	return exit.Code(err)
}
