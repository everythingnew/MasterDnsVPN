package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/udpserver"
)

func main() {
	cfg, err := config.LoadServerConfig("server_config.toml")
	if err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("load config failed: %v\n", err))
		os.Exit(1)
	}

	log := logger.New("MasterDnsVPN Go Server", cfg.LogLevel)
	srv := udpserver.New(cfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Infof("<green>starting UDP server</green> on <cyan>%s</cyan>", cfg.Address())

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("<red>server stopped with error</red>: <yellow>%v</yellow>", err)
		os.Exit(1)
	}

	log.Infof("<yellow>server stopped</yellow>")
}
