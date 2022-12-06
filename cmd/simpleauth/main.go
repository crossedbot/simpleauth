package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/crossedbot/common/golang/config"
	"github.com/crossedbot/common/golang/logger"
	"github.com/crossedbot/common/golang/server"
	"github.com/crossedbot/common/golang/service"

	"github.com/crossedbot/simpleauth/pkg/controller"
)

const (
	FatalExitcode = iota + 1
)

type Config struct {
	Host         string `toml:"host"`
	Port         int    `toml:"port"`
	ReadTimeout  int    `toml:"read_timeout"`  // in seconds
	WriteTimeout int    `toml:"write_timeout"` // in seconds
}

func main() {
	ctx := context.Background()
	svc := service.New(ctx)
	if err := svc.Run(run, syscall.SIGINT, syscall.SIGTERM); err != nil {
		fatal("Error: %s", err)
	}
}

func fatal(format string, a ...interface{}) {
	logger.Error(fmt.Errorf(format, a...))
	os.Exit(FatalExitcode)
}

func newServer(c Config) server.Server {
	hostport := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	srv := server.New(
		hostport,
		c.ReadTimeout,
		c.WriteTimeout,
	)
	for _, route := range controller.Routes {
		srv.Add(
			route.Handler,
			route.Method,
			route.Path,
			route.ResponseSettings...,
		)
	}
	return srv
}

func run(ctx context.Context) error {
	f := flags()
	config.Path(f.ConfigFile)
	var c Config
	if err := config.Load(&c); err != nil {
		return err
	}
	// Call the controller to initialize it and ensure no problems before the
	// server request.
	controller.Ctrl()
	srv := newServer(c)
	if err := srv.Start(); err != nil {
		return err
	}
	logger.Info(fmt.Sprintf("Listening on %s:%d", c.Host, c.Port))
	<-ctx.Done()
	logger.Info("Received signal, shutting down...")
	return nil
}
