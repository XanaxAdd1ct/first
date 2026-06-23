package main

import (
    "log/slog"
    "os"
)

func NewLogger(level string) *slog.Logger {
    var lvl slog.Level
    if err := lvl.UnmarshalText([]byte(level)); err != nil {
        lvl = slog.LevelInfo
    }
    return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level:     lvl,
        AddSource: true,
    }))
}