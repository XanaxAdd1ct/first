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
        slog.Error("load config", slog.String("err", err.Error()))
        os.Exit(1)
    }

    log := NewLogger(cfg.LogLevel)

    if err := run(cfg, log); err != nil {
        log.Error("fatal error", slog.String("err", err.Error()))
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
            log.Warn("storage close error", slog.String("err", err.Error()))
        }
    }()

    keyRing, err := NewKeyRing(cfg.HMACSecret.Value())
    if err != nil {
        return fmt.Errorf("init keyring: %w", err)
    }

    srv, err := New(
        &APIConfig{
            AdminToken:      cfg.AdminToken.Value(),
            DefaultDomain:   cfg.DefaultDomain,
            DefaultRedirect: cfg.DefaultRedirect,
        },
        store,
        keyRing,
        log,
        prometheus.DefaultRegisterer,
    )
    if err != nil {
        return fmt.Errorf("init server: %w", err)
    }

    httpSrv := buildHTTPServer(cfg, srv)

    return serveWithGracefulShutdown(httpSrv, cfg, log)
}

// buildHTTPServer собирает http.Server с правильными таймаутами и TLS
//
// таймауты выставлены консервативно:
//   - ReadHeaderTimeout 5s  защита от slowloris
//   - ReadTimeout 15s  максимум на чтение тела запроса
//   - WriteTimeout 15s  максимум на отправку ответа
//   - IdleTimeout 30s  keep-alive соединения
//   - MaxHeaderBytes 64kb  защита от огромных заголовков
//
// TLS включается только если заданы оба пути к сертификату и ключу
// MinVersion TLS 1.3  запрещает устаревшие уязвимые версии
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
            MinVersion:               tls.VersionTLS13,
            PreferServerCipherSuites: true,
            CurvePreferences: []tls.CurveID{
                tls.X25519,
                tls.CurveP256,
            },
            CipherSuites: []uint16{
                tls.TLS_AES_128_GCM_SHA256,
                tls.TLS_AES_256_GCM_SHA384,
                tls.TLS_CHACHA20_POLY1305_SHA256,
            },
        }
    }

    return srv
}

// serveWithGracefulShutdown запускает сервер и обрабатывает SIGINT/SIGTERM
//
// если заданы TLS сертификаты  запускает HTTPS  иначе HTTP
// http.ErrServerClosed не ошибка  штатное завершение после Shutdown()
// после сигнала даём shutdownTimeout на завершение текущих запросов
func serveWithGracefulShutdown(srv *http.Server, cfg *Config, log *slog.Logger) error {
    serverErr := make(chan error, 1)

    go func() {
        log.Info("server starting",
            slog.String("addr", srv.Addr),
            slog.Bool("tls", cfg.TLSCertFile != ""),
        )

        var err error
        if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
            err = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
        } else {
            log.Warn("TLS not configured  running without HTTPS")
            err = srv.ListenAndServe()
        }

        if errors.Is(err, http.ErrServerClosed) {
            serverErr <- nil
        } else {
            serverErr <- fmt.Errorf("listen and serve: %w", err)
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    defer signal.Stop(quit)

    select {
    case err := <-serverErr:
        return err
    case sig := <-quit:
        log.Info("shutdown signal received", slog.String("signal", sig.String()))
    }

    ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
    defer cancel()

    log.Info("shutting down server")
    if err := srv.Shutdown(ctx); err != nil {
        return fmt.Errorf("graceful shutdown: %w", err)
    }

    log.Info("server stopped")
    return nil
}
