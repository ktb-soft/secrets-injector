// Command secrets-injector is a Docker Compose provider that fetches secrets
// from a configured backend and injects them into depending services.
package main

import (
	"context"
	"fmt"
	"os"

	_ "github.com/ktb-soft/secrets-injector/internal/backend/onepassword"
	"github.com/ktb-soft/secrets-injector/internal/protocol"
	"github.com/ktb-soft/secrets-injector/internal/provider"
)

func main() {
	os.Exit(run())
}

// run returns the process exit code. main stays a single statement so that
// os.Exit never skips a deferred call.
func run() int {
	emitter := protocol.New(os.Stdout)

	inv, err := provider.ParseInvocation(os.Args[1:])
	if err != nil {
		emitter.Error("%v", err)
		return 1
	}

	if err := provider.Run(context.Background(), emitter, inv); err != nil {
		emitter.Error("%v", err)
		return 1
	}

	// A failure writing the protocol stream cannot be reported on that stream.
	if err := emitter.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
