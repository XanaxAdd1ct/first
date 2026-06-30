package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "path/filepath"
    "sync"
    "sync/atomic"
    "time"

    "github.com/gin-gonic/gin"
)

const (
    maxAuthFailures     = 5
    authWindowDuration  = time.Minute
    ddosThreshold       = 50
    ddosWindowDuration  = time.Second
    maxEventsPerIP      = 1000
    cleanupInterval     = time.Minute
    ipRetentionDuration = time.Hour
    ddosLogCooldown     = 5 * time.Second
    archiveWorkers      = 4
    archiveQueueSize    = 256
)

type suspiciousEvent struct {
    At   time.Time `json:"at"`
    Kind string    `json:"kind"`
}

type ipRecord struct {
    mu          sync.Mutex
    events      [maxEventsPerIP]suspiciousEvent
    count       int
    head        int
    total       uint64
    suspicious  int32
    lastDDOSLog int64
    flushLock   int32
}

func (r *ipRecord) add(now time.Time, kind string, window time.Duration) int {
    r.mu.Lock()
    defer r.mu.Unlock()

    tail := (r.head + r.count) % maxEventsPerIP
    r.events[tail] = suspiciousEvent{At: now, Kind: kind}

    if r.count < maxEventsPerIP {
        r.count++
    } else {
        r.head = (r.head + 1) % maxEventsPerIP
    }
    r.total++

    cutoff := now.Add(-window)
    n := 0
    for i := 0; i < r.count; i++ {
        e := r.events[(r.head+i)%maxEventsPerIP]
        if !e.At.Before(cutoff) && e.Kind == kind {
            n++
        }
    }
    return n
}

func (r *ipRecord) snapshot() []suspiciousEvent {
    out := make([]suspiciousEvent, r.count)
    for i := 0; i < r.count; i++ {
        out[i] = r.events[(r.head+i)%maxEventsPerIP]
    }
    return out
}

func (r *ipRecord) isSuspicious() bool {
    return atomic.LoadInt32(&r.suspicious) == 1
}

func (r *ipRecord) markSuspicious() {
    atomic.StoreInt32(&r.suspicious, 1)
}

func (r *ipRecord) clearSuspicious() {
    atomic.StoreInt32(&r.suspicious, 0)
}

func (r *ipRecord) tryLockFlush() bool {
    return atomic.CompareAndSwapInt32(&r.flushLock, 0, 1)
}

func (r *ipRecord) unlockFlush() {
    atomic.StoreInt32(&r.flushLock, 0)
}

func (r *ipRecord) shouldLogDDOS(now time.Time) bool {
    last := atomic.LoadInt64(&r.lastDDOSLog)
    if now.UnixNano()-last < int64(ddosLogCooldown) {
        return false
    }
    return atomic.CompareAndSwapInt64(&r.lastDDOSLog, last, now.UnixNano())
}

type archiveTask struct {
    ip     string
    events []suspiciousEvent
}

type SecurityConfig struct {
    ArchiveDir string
}

type SecurityMonitor struct {
    mu      sync.RWMutex
    records map[string]*ipRecord
    log     *slog.Logger
    cfg     SecurityConfig
    ctx     context.Context
    cancel  context.CancelFunc
    queue   chan archiveTask
    wg      sync.WaitGroup
}

func NewSecurityMonitor(log *slog.Logger, cfg SecurityConfig) *SecurityMonitor {
    if cfg.ArchiveDir == "" {
        cfg.ArchiveDir = "security_archives"
    }

    ctx, cancel := context.WithCancel(context.Background())
    m := &SecurityMonitor{
        records: make(map[string]*ipRecord),
        log:     log,
        cfg:     cfg,
        ctx:     ctx,
        cancel:  cancel,
        queue:   make(chan archiveTask, archiveQueueSize),
    }

    for i := 0; i < archiveWorkers; i++ {
        m.wg.Add(1)
        go m.archiveWorker()
    }

    m.wg.Add(1)
    go m.cleanup()

    return m
}

func (m *SecurityMonitor) Shutdown() {
    m.cancel()
    m.wg.Wait()
}

func (m *SecurityMonitor) getOrCreate(ip string) *ipRecord {
    m.mu.RLock()
    rec, ok := m.records[ip]
    m.mu.RUnlock()
    if ok {
        return rec
    }

    m.mu.Lock()
    defer m.mu.Unlock()
    if rec, ok = m.records[ip]; ok {
        return rec
    }
    rec = &ipRecord{}
    m.records[ip] = rec
    return rec
}

func (m *SecurityMonitor) cleanup() {
    defer m.wg.Done()
    ticker := time.NewTicker(cleanupInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            m.doCleanup()
        case <-m.ctx.Done():
            return
        }
    }
}

func (m *SecurityMonitor) doCleanup() {
    cutoff := time.Now().Add(-ipRetentionDuration)

    m.mu.Lock()
    defer m.mu.Unlock()

    for ip, rec := range m.records {
        if rec.isSuspicious() {
            continue
        }
        rec.mu.Lock()
        hasRecent := false
        for i := 0; i < rec.count; i++ {
            if rec.events[(rec.head+i)%maxEventsPerIP].At.After(cutoff) {
                hasRecent = true
                break
            }
        }
        rec.mu.Unlock()

        if !hasRecent {
            delete(m.records, ip)
        }
    }
}

func (m *SecurityMonitor) archiveWorker() {
    defer m.wg.Done()
    for {
        select {
        case task, ok := <-m.queue:
            if !ok {
                return
            }
            m.processArchive(task)
        case <-m.ctx.Done():
            for {
                select {
                case task := <-m.queue:
                    m.processArchive(task)
                default:
                    return
                }
            }
        }
    }
}

func (m *SecurityMonitor) tryEnqueueFlush(ip string, rec *ipRecord) {
    if !rec.tryLockFlush() {
        return
    }

    rec.mu.Lock()
    if rec.count < maxEventsPerIP {
        rec.mu.Unlock()
        rec.unlockFlush()
        return
    }
    events := rec.snapshot()
    rec.count = 0
    rec.head = 0
    rec.mu.Unlock()

    task := archiveTask{ip: ip, events: events}

    select {
    case m.queue <- task:
    default:
        m.log.Warn("security: archive queue full, dropping task",
            slog.String("ip", ip),
            slog.Int("events", len(events)),
        )
        rec.unlockFlush()
        return
    }

    rec.unlockFlush()
}

func (m *SecurityMonitor) processArchive(task archiveTask) {
    data, err := json.MarshalIndent(map[string]any{
        "ip":          task.ip,
        "archived_at": time.Now().UTC(),
        "total":       len(task.events),
        "events":      task.events,
    }, "", "  ")
    if err != nil {
        m.log.Error("archive: marshal failed",
            slog.String("ip", task.ip),
            slog.String("err", err.Error()),
        )
        return
    }

    ts := time.Now().UTC().Format("20060102_150405")
    name := fmt.Sprintf("%s_%s.json", sanitizeIP(task.ip), ts)

    m.log.Info("archiving ip events",
        slog.String("ip", task.ip),
        slog.Int("events", len(task.events)),
        slog.String("file", name),
    )

    m.saveLocally(name, data)
}

func (m *SecurityMonitor) saveLocally(name string, data []byte) {
    if err := os.MkdirAll(m.cfg.ArchiveDir, 0755); err != nil {
        m.log.Error("archive: mkdir failed", slog.String("err", err.Error()))
        return
    }
    path := filepath.Join(m.cfg.ArchiveDir, name)
    if err := os.WriteFile(path, data, 0644); err != nil {
        m.log.Error("archive: write failed", slog.String("err", err.Error()))
        return
    }
    m.log.Info("archive saved", slog.String("path", path))
}

func (m *SecurityMonitor) OnAuthFailure(ip, path string) {
    rec := m.getOrCreate(ip)
    m.tryEnqueueFlush(ip, rec)

    failures := rec.add(time.Now(), "auth_failure", authWindowDuration)

    m.log.Warn("auth failure",
        slog.String("ip", ip),
        slog.String("path", path),
        slog.Int("failures_last_minute", failures),
    )

    if failures >= maxAuthFailures && !rec.isSuspicious() {
        rec.markSuspicious()
        m.log.Error("POSSIBLE BRUTEFORCE DETECTED",
            slog.String("ip", ip),
            slog.String("path", path),
            slog.Int("failures_last_minute", failures),
        )
    }
}

func (m *SecurityMonitor) OnRateLimit(ip string) {
    rec := m.getOrCreate(ip)
    m.tryEnqueueFlush(ip, rec)

    now := time.Now()
    hits := rec.add(now, "rate_limit", ddosWindowDuration)

    if rec.shouldLogDDOS(now) && hits >= ddosThreshold {
        if !rec.isSuspicious() {
            rec.markSuspicious()
        }
        m.log.Error("POSSIBLE DDOS DETECTED",
            slog.String("ip", ip),
            slog.Int("rate_limit_hits_per_second", hits),
        )
    }
}

func (m *SecurityMonitor) ClearSuspicious(ip string) {
    m.mu.RLock()
    rec, ok := m.records[ip]
    m.mu.RUnlock()

    if !ok {
        return
    }

    rec.clearSuspicious()
    m.log.Info("suspicious ip cleared", slog.String("ip", ip))
}

func (m *SecurityMonitor) ListSuspicious() []string {
    m.mu.RLock()
    defer m.mu.RUnlock()

    out := make([]string, 0, len(m.records))
    for ip, rec := range m.records {
        if rec.isSuspicious() {
            out = append(out, ip)
        }
    }
    return out
}

func SecurityMiddleware(monitor *SecurityMonitor) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()
        switch c.Writer.Status() {
        case http.StatusUnauthorized, http.StatusForbidden:
            monitor.OnAuthFailure(c.ClientIP(), c.Request.URL.Path)
        case http.StatusTooManyRequests:
            monitor.OnRateLimit(c.ClientIP())
        }
    }
}

func sanitizeIP(ip string) string {
    out := make([]byte, 0, len(ip))
    for i := 0; i < len(ip); i++ {
        c := ip[i]
        if c == '.' || c == ':' {
            c = '_'
        }
        out = append(out, c)
    }
    return string(out)
}
