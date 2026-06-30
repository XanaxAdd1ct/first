package main

import (
    "context"
    "errors"
    "io"
    "log/slog"
    "net"
    "net/http"
    "testing"
    "time"
)

func testLogger() *slog.Logger {
    return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testConfig() *Config {
    return &Config{
        TLSCertFile: "",
        TLSKeyFile:  "",
    }
}

func freePort(t *testing.T) string {
    t.Helper()
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatalf("freePort: %v", err)
    }
    defer ln.Close()
    return ln.Addr().String()
}

func waitForServer(addr string, timeout time.Duration) error {
    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
        if err == nil {
            conn.Close()
            return nil
        }
        time.Sleep(50 * time.Millisecond)
    }
    return errors.New("server did not become ready in time")
}

func TestServeWithGracefulShutdown_StartsAndStops(t *testing.T) {
    addr := freePort(t)
    srv := &http.Server{
        Addr:    addr,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
    }

    done := make(chan error, 1)
    go func() {
        done <- serveWithGracefulShutdown(srv, testConfig(), testLogger())
    }()

    if err := waitForServer(addr, 2*time.Second); err != nil {
        t.Fatalf("server did not start: %v", err)
    }

    if err := srv.Shutdown(context.Background()); err != nil {
        t.Fatalf("shutdown: %v", err)
    }

    select {
    case err := <-done:
        if err != nil {
            t.Errorf("unexpected error: %v", err)
        }
    case <-time.After(3 * time.Second):
        t.Error("server did not stop in time")
    }
}

func TestServeWithGracefulShutdown_RespondsToRequests(t *testing.T) {
    addr := freePort(t)
    srv := &http.Server{
        Addr: addr,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.WriteHeader(http.StatusOK)
        }),
    }

    go serveWithGracefulShutdown(srv, testConfig(), testLogger())
    defer srv.Shutdown(context.Background())

    if err := waitForServer(addr, 2*time.Second); err != nil {
        t.Fatalf("server did not start: %v", err)
    }

    resp, err := http.Get("http://" + addr)
    if err != nil {
        t.Fatalf("GET: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Errorf("want 200, got %d", resp.StatusCode)
    }
}

func TestServeWithGracefulShutdown_InvalidAddr(t *testing.T) {
    srv := &http.Server{
        Addr:    "invalid-addr-that-does-not-exist:99999",
        Handler: http.NewServeMux(),
    }

    err := serveWithGracefulShutdown(srv, testConfig(), testLogger())
    if err == nil {
        t.Error("expected error for invalid addr, got nil")
    }
}

func TestServeWithGracefulShutdown_ShutdownTimeout(t *testing.T) {
    addr := freePort(t)

    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(100 * time.Millisecond)
        w.WriteHeader(http.StatusOK)
    })

    srv := &http.Server{
        Addr:    addr,
        Handler: handler,
    }

    go serveWithGracefulShutdown(srv, testConfig(), testLogger())

    if err := waitForServer(addr, 2*time.Second); err != nil {
        t.Fatalf("server did not start: %v", err)
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        t.Errorf("shutdown: %v", err)
    }
}

func TestNewLogger_NotNil(t *testing.T) {
    log := NewLogger("info")
    if log == nil {
        t.Error("NewLogger returned nil")
    }
}

func TestNewLogger_InvalidLevel(t *testing.T) {
    log := NewLogger("invalid")
    if log == nil {
        t.Error("NewLogger returned nil for invalid level")
    }
}
