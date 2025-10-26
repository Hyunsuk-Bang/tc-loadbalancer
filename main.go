// main.go
package main

import (
	"context"
	"flag"
	"lb/internal/loadbalancer"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
)

func main() {
	debug := flag.Bool("debug", false, "sets log level to debug")
	bpfForwarder := flag.Bool("bpf", false, "use bpf for forwarding")
	configFile := flag.String("config", "example/example.yaml", "config files")
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	lbCfg, err := loadbalancer.ParseFile(*configFile)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		cancel()
	}()

	if !*bpfForwarder {
		loadbalancer.RunSocketLB(ctx, lbCfg)
	} else {
		loadbalancer.RunTCLB(ctx, lbCfg)
	}
}
