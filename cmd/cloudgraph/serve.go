package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/TroubieD3v/cloudgraph/internal/server"
	"github.com/TroubieD3v/cloudgraph/internal/store"
	"github.com/TroubieD3v/cloudgraph/internal/ui"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (keep it on loopback: the API has no authentication)")
	db := fs.String("db", "cloudgraph.db", "SQLite database path (use :memory: for no persistence)")
	lim := searchFlags(fs)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if err := lim.Validate(); err != nil {
		return err
	}
	if host, _, err := net.SplitHostPort(*addr); err == nil && host != "127.0.0.1" && host != "localhost" && host != "::1" {
		fmt.Fprintln(os.Stderr, "warning: listening on a non-loopback address; CloudGraph has no authentication")
	}
	st, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.New(st, ui.FS()).WithLimits(*lim).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	fmt.Printf("CloudGraph %s listening on http://%s (database: %s)\n", version, *addr, *db)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
