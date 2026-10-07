// Command heain-console serves the web screens for heain-core's admin plane
// behind heain-gateway (Step 5b). Configured through the heain-sdk HEAIN_*
// variables; runs however the operator likes.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/heainframework/heain-console/internal/console"
	"github.com/heainframework/heain-sdk/heain"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	log.Printf("heain-console: registered (%s), waiting for admission", app.Status())
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	c := &console.Console{Core: app.Core, Logf: log.Printf}
	srv := app.NewServer()
	if err := c.Register(srv); err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", heain.Listen(":19590"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("heain-console: active on %s", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = app.Close(context.Background())
	log.Printf("heain-console: deregistered")
}
