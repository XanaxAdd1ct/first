package main

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/prometheus/client_golang/prometheus"
)

const shutdownTimeout = 10 * time.Second

func main() {
    cfg, err := Load()
    if err != nil {
        slog.Error("load config", "err", err)
        os.Exit(1)
    }

    log := NewLogger(cfg.LogLevel)

    if err := run(cfg, log); err != nil {
        log.Error("fatal error", "err", err)
        os.Exit(1)
    }
}

func run(cfg *Config, log *slog.Logger) error {
    store, err := NewStorage(cfg.RedisURL, cfg.RedisTTLDuration())
    if err != nil {
        return fmt.Errorf("init storage: %w", err)
    }
    defer func() {
        if err := store.Close(); err != nil {
            log.Warn("storage close error", "err", err)
        }
    }()

    nonces := newNonceStore()
    defer nonces.shutdown()

    keyRing, err := NewKeyRing(cfg.HMACSecret.Value())
    if err != nil {
        return fmt.Errorf("init keyring: %w", err)
    }

    srv, err := New(
        &APIConfig{
            AdminToken:      cfg.AdminToken.Value(),
            DefaultDomain:   cfg.DefaultDomain,
            DefaultRedirect: cfg.DefaultRedirect,
            AdminAllowedIPs: cfg.AdminAllowedIPs,
        },
        store,
        keyRing,
        nonces,
        log,
        prometheus.DefaultRegisterer,
    )
    if err != nil {
        return fmt.Errorf("init server: %w", err)
    }

    httpSrv := buildHTTPServer(cfg, srv)

    return serveWithGracefulShutdown(httpSrv, cfg, log)
}

func buildHTTPServer(cfg *Config, handler http.Handler) *http.Server {
    srv := &http.Server{
        Addr:              cfg.ListenAddr(),
        Handler:           handler,
        ReadHeaderTimeout: 5 * time.Second,
        ReadTimeout:       15 * time.Second,
        WriteTimeout:      15 * time.Second,
        IdleTimeout:       30 * time.Second,
        MaxHeaderBytes:    1 << 16,
    }

    if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
        srv.TLSConfig = &tls.Config{
            MinVersion: tls.VersionTLS13,
        }
    }

    return srv
}

func serveWithGracefulShutdown(srv *http.Server, cfg *Config, log *slog.Logger) error {
    serverErr := make(chan error, 1)

    go func() {
        log.Info("server starting", "addr", srv.Addr, "tls", cfg.TLSCertFile != "")
        var err error
        if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
            err = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
        } else {
            log.Warn("running without HTTPS")
            err = srv.ListenAndServe()
        }

        if errors.Is(err, http.ErrServerClosed) {
            serverErr <- nil
        } else {
            serverErr <- err
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    defer signal.Stop(quit)

    select {
    case err := <-serverErr:
        return err
    case sig := <-quit:
        log.Info("shutdown signal received", "signal", sig.String())
    }

    ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        return fmt.Errorf("graceful shutdown: %w", err)
    }

    log.Info("server stopped")
    return nil
}
