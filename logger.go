package main

import (
    "io"
    "log/slog"
    "os"
    "sync"
    "time"
)

func NewLogger(level string) *slog.Logger {
    var lvl slog.Level
    if err := lvl.UnmarshalText([]byte(level)); err != nil {
        lvl = slog.LevelInfo
    }

    rw := &rotatingWriter{
        path:     "logs.json",
        maxBytes: 100 * 1024 * 1024,
    }

    multi := io.MultiWriter(os.Stdout, rw)

    return slog.New(slog.NewJSONHandler(multi, &slog.HandlerOptions{
        Level:     lvl,
        AddSource: true,
    }))
}

type rotatingWriter struct {
    mu       sync.Mutex
    path     string
    maxBytes int64
    file     *os.File
    size     int64
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
    w.mu.Lock()
    defer w.mu.Unlock()

    if w.file == nil {
        if err := w.open(); err != nil {
            return 0, err
        }
    }

    if w.size+int64(len(p)) > w.maxBytes {
        if err := w.rotate(); err != nil {
            return 0, err
        }
    }

    n, err := w.file.Write(p)
    w.size += int64(n)
    return n, err
}

func (w *rotatingWriter) open() error {
    f, err := os.OpenFile(w.path,
        os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    info, err := f.Stat()
    if err != nil {
        f.Close()
        return err
    }
    w.file = f
    w.size = info.Size()
    return nil
}

func (w *rotatingWriter) rotate() error {
    if w.file != nil {
        if err := w.file.Close(); err != nil {
            return err
        }
        w.file = nil
    }

    rotated := w.path + "." + time.Now().UTC().Format("20060102_150405")
    if err := os.Rename(w.path, rotated); err != nil {
        return err
    }

    return w.open()
}
