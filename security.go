// мониторинг подозрительной активности и защита от атак
//
// следит за брутфорсом и ddos  не блокирует запросы сам
// блокировку делает rate limiter  монитор собирает доказательства
// при накоплении 1000 событий с одного ip  упаковывает их в zip
// и отправляет в телеграм или сохраняет локально

package main

import (
    "archive/zip"
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log/slog"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"
    "sync"
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
)
// suspiciousEvent одно подозрительное событие с временной меткой
// kind может быть auth_failure или rate_limit
// сериализуется в json при архивировании
type suspiciousEvent struct {
    At   time.Time `json:"at"`
    Kind string    `json:"kind"`
}
// ipRecord хранит историю событий с одного ip в кольцевом буфере
//
// кольцевой буфер выбран намеренно  фиксированный размер памяти
// при переполнении старые события затираются новыми автоматически
// свой мьютекс у каждой записи  чтобы не блокировать весь монитор
// пока идёт архивирование одного ip
//
// suspicious не удаляется автоматически  только вручную через ClearSuspicious
// это важно  злоумышленник должен оставаться в списке пока его не проверили
type ipRecord struct {
    mu          sync.Mutex
    events      [maxEventsPerIP]suspiciousEvent
    count       int  // сколько всего записано  максимум maxEventsPerIP
    head        int  // индекс самого старого события
    total       uint64
    suspicious  bool
    lastDDOSLog time.Time
}

// add добавляет событие в кольцевой буфер
// когда буфер заполнен  перезаписывает самое старое событие
// возвращает количество событий данного kind за указанное окно
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
        idx := (r.head + i) % maxEventsPerIP
        e := r.events[idx]
        if e.At.Before(cutoff) {
            continue
        }
        if e.Kind == kind {
            n++
        }
    }
    return n
}

// add добавляет событие в кольцевой буфер и считает похожие события за окно
//
// алгоритм:
//   1. вычисляем позицию tail = (head + count) % maxEventsPerIP
//   2. записываем событие на позицию tail
//   3. если буфер полон  двигаем head вперёд  затирая старейшее событие
//   4. обходим все count элементов начиная с head  считаем нужный kind за окно
//
// обходим все элементы без break  потому что ring buffer не гарантирует
// хронологический порядок после переполнения
func (r *ipRecord) snapshot() []suspiciousEvent {
    out := make([]suspiciousEvent, r.count)
    for i := 0; i < r.count; i++ {
        out[i] = r.events[(r.head+i)%maxEventsPerIP]
    }
    return out
}

// isFull возвращает true если буфер заполнен
func (r *ipRecord) isFull() bool {
    r.mu.Lock()
    defer r.mu.Unlock()
    return r.count == maxEventsPerIP
}

// SecurityConfig конфигурация монитора
// TelegramToken и TelegramChatID опциональны
// если не заданы  архив сохраняется локально в ArchiveDir
type SecurityConfig struct {
    TelegramToken  string
    TelegramChatID string
    ArchiveDir     string
}

type SecurityMonitor struct {
    mu      sync.Mutex
    records map[string]*ipRecord
    log     *slog.Logger
    cfg     SecurityConfig
    ctx     context.Context
    cancel  context.CancelFunc
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
    }
    go m.cleanup()
    return m
}

func (m *SecurityMonitor) Shutdown() {
    m.cancel()
}

// getOrCreate возвращает запись для ip  создаёт если нет
func (m *SecurityMonitor) getOrCreate(ip string) *ipRecord {
    m.mu.Lock()
    defer m.mu.Unlock()
    rec, ok := m.records[ip]
    if !ok {
        rec = &ipRecord{}
        m.records[ip] = rec
    }
    return rec
}

// cleanup удаляет старые обычные записи
// подозрительные не трогает никогда
func (m *SecurityMonitor) cleanup() {
    ticker := time.NewTicker(cleanupInterval)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            m.mu.Lock()
            cutoff := time.Now().Add(-ipRetentionDuration)
            for ip, rec := range m.records {
                rec.mu.Lock()
                if rec.suspicious {
                    rec.mu.Unlock()
                    continue
                }
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
            m.mu.Unlock()
        case <-m.ctx.Done():
            return
        }
    }
}

// archiveAndFlush снимает снепшот событий  упаковывает в zip
// отправляет в телеграм или сохраняет локально  затем очищает буфер
func (m *SecurityMonitor) archiveAndFlush(ip string, rec *ipRecord) {
    rec.mu.Lock()
    events := rec.snapshot()
    rec.count = 0
    rec.head = 0
    rec.mu.Unlock()

    data, err := json.MarshalIndent(map[string]interface{}{
        "ip":         ip,
        "archived_at": time.Now().UTC(),
        "events":     events,
    }, "", "  ")
    if err != nil {
        m.log.Error("archive: marshal failed", slog.String("ip", ip), slog.String("err", err.Error()))
        return
    }

    var buf bytes.Buffer
    zw := zip.NewWriter(&buf)
    filename := fmt.Sprintf("%s_%s.json", ip, time.Now().UTC().Format("20060102_150405"))
    fw, err := zw.Create(filename)
    if err != nil {
        m.log.Error("archive: create zip entry failed", slog.String("err", err.Error()))
        return
    }
    if _, err := fw.Write(data); err != nil {
        m.log.Error("archive: write zip entry failed", slog.String("err", err.Error()))
        return
    }
    if err := zw.Close(); err != nil {
        m.log.Error("archive: close zip failed", slog.String("err", err.Error()))
        return
    }

    zipName := filename[:len(filename)-5] + ".zip"
    m.log.Info("archiving ip events",
        slog.String("ip", ip),
        slog.Int("events", len(events)),
        slog.String("file", zipName),
    )

    if m.cfg.TelegramToken != "" && m.cfg.TelegramChatID != "" {
        if err := m.sendToTelegram(zipName, buf.Bytes()); err != nil {
            m.log.Error("archive: telegram send failed",
                slog.String("err", err.Error()),
                slog.String("fallback", "saving locally"),
            )
            m.saveLocally(zipName, buf.Bytes())
        }
        return
    }

    m.saveLocally(zipName, buf.Bytes())
}

// saveLocally сохраняет архив в ArchiveDir
func (m *SecurityMonitor) saveLocally(name string, data []byte) {
    if err := os.MkdirAll(m.cfg.ArchiveDir, 0755); err != nil {
        m.log.Error("archive: mkdir failed", slog.String("err", err.Error()))
        return
    }
    path := filepath.Join(m.cfg.ArchiveDir, name)
    if err := os.WriteFile(path, data, 0644); err != nil {
        m.log.Error("archive: write file failed", slog.String("err", err.Error()))
        return
    }
    m.log.Info("archive saved", slog.String("path", path))
}

// sendToTelegram отправляет zip файл в telegram через Bot API
func (m *SecurityMonitor) sendToTelegram(filename string, data []byte) error {
    var body bytes.Buffer
    writer := multipart.NewWriter(&body)

    if err := writer.WriteField("chat_id", m.cfg.TelegramChatID); err != nil {
        return fmt.Errorf("write chat_id: %w", err)
    }
    if err := writer.WriteField("caption", fmt.Sprintf("security archive: %s", filename)); err != nil {
        return fmt.Errorf("write caption: %w", err)
    }

    part, err := writer.CreateFormFile("document", filename)
    if err != nil {
        return fmt.Errorf("create form file: %w", err)
    }
    if _, err := io.Copy(part, bytes.NewReader(data)); err != nil {
        return fmt.Errorf("copy file: %w", err)
    }
    if err := writer.Close(); err != nil {
        return fmt.Errorf("close writer: %w", err)
    }

    url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", m.cfg.TelegramToken)
    req, err := http.NewRequestWithContext(m.ctx, http.MethodPost, url, &body)
    if err != nil {
        return fmt.Errorf("new request: %w", err)
    }
    req.Header.Set("Content-Type", writer.FormDataContentType())

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return fmt.Errorf("do request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("telegram api returned %d", resp.StatusCode)
    }
    return nil
}

func (m *SecurityMonitor) OnAuthFailure(ip, path string) {
    rec := m.getOrCreate(ip)

    if rec.isFull() {
        go m.archiveAndFlush(ip, rec)
    }

    failures := rec.add(time.Now(), "auth_failure", authWindowDuration)

    m.log.Warn("auth failure",
        slog.String("ip", ip),
        slog.String("path", path),
        slog.Int("failures_last_minute", failures),
    )

    if failures >= maxAuthFailures {
        rec.mu.Lock()
        rec.suspicious = true
        rec.mu.Unlock()

        m.log.Error("POSSIBLE BRUTEFORCE DETECTED",
            slog.String("ip", ip),
            slog.String("path", path),
            slog.Int("failures_last_minute", failures),
        )
    }
}

func (m *SecurityMonitor) OnRateLimit(ip string) {
    rec := m.getOrCreate(ip)

    if rec.isFull() {
        go m.archiveAndFlush(ip, rec)
    }

    now := time.Now()
    hits := rec.add(now, "rate_limit", ddosWindowDuration)

    rec.mu.Lock()
    shouldLog := now.Sub(rec.lastDDOSLog) > ddosLogCooldown
    if shouldLog {
        rec.lastDDOSLog = now
    }
    rec.mu.Unlock()

    if shouldLog && hits >= ddosThreshold {
        rec.mu.Lock()
        rec.suspicious = true
        rec.mu.Unlock()

        m.log.Error("POSSIBLE DDOS DETECTED",
            slog.String("ip", ip),
            slog.Int("rate_limit_hits_per_second", hits),
        )
    }
}

func (m *SecurityMonitor) ClearSuspicious(ip string) {
    m.mu.Lock()
    rec, ok := m.records[ip]
    m.mu.Unlock()
    if !ok {
        return
    }
    rec.mu.Lock()
    rec.suspicious = false
    rec.mu.Unlock()
    m.log.Info("suspicious ip cleared", slog.String("ip", ip))
}

func (m *SecurityMonitor) ListSuspicious() []string {
    m.mu.Lock()
    defer m.mu.Unlock()
    out := make([]string, 0)
    for ip, rec := range m.records {
        rec.mu.Lock()
        if rec.suspicious {
            out = append(out, ip)
        }
        rec.mu.Unlock()
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
