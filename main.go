// точка входа  намеренно тонкая  только сборка зависимостей и запуск
//
// вся логика в run() а не в main()  это позволяет тестировать
// запуск без os.Exit и даёт нормальные коды возврата

package main

import (
    "context"
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

// shutdownTimeout сколько ждём завершения in-flight запросов при shutdown
//
// 10 секунд выбраны с запасом  handlerTimeout в api.go тоже 10 секунд
// значит самый долгий запрос успеет завершиться до того как мы отрубим сервер

const shutdownTimeout = 10 * time.Second

// main читает конфиг и запускает сервис
//
// при любой ошибке инициализации  os.Exit(1)
// это намеренно  если не можем стартовать  лучше упасть быстро
// чем висеть в невалидном состоянии  оркестратор поднимет заново

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

// run собирает все зависимости и запускает http сервер
//
// порядок инициализации важен  storage  keyring  server  http
// каждый следующий зависит от предыдущего
// defer store.Close() гарантирует закрытие соединения с Redis
// даже если что то упало при инициализации дальше по цепочке

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

    httpSrv := &http.Server{
        Addr:              cfg.ListenAddr(),
        Handler:           srv,
        ReadHeaderTimeout: 10 * time.Second,
        ReadTimeout:       30 * time.Second,
        WriteTimeout:      30 * time.Second,
        IdleTimeout:       60 * time.Second,
    }

    return serveWithGracefulShutdown(httpSrv, log)
}

// serveWithGracefulShutdown запускает сервер и обрабатывает SIGINT/SIGTERM
//
// два канала  serverErr ошибка ListenAndServe и quit сигнал ОС
// select блокируется на обоих  первый победивший определяет что делать
//
// http.ErrServerClosed это не ошибка  штатное завершение после Shutdown()
// всё остальное реальная проблема  порт занят  нет прав и тд
//
// после сигнала даём сервису shutdownTimeout на завершение текущих запросов
// по истечению таймаута http.Server.Shutdown вернёт context.DeadlineExceeded
// мы пробрасываем это как ошибку и выходим с кодом 1

func serveWithGracefulShutdown(srv *http.Server, log *slog.Logger) error {
    serverErr := make(chan error, 1)

    go func() {
        log.Info("server starting", slog.String("addr", srv.Addr))
        if err := srv.ListenAndServe(); errors.Is(err, http.ErrServerClosed) {
            serverErr <- nil // внешний Shutdown — штатное завершение
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