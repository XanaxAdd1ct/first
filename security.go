package main

import (
    "log/slog"
    "net/http"
    "sync"
    "time"

    "github.com/gin-gonic/gin"
)

const (
    // максимум неудачных попыток авторизации с одного ip
    // после этого ip считается подозрительным
    maxAuthFailures = 5

    // окно времени в котором считаются неудачные попытки
    authWindowDuration = time.Minute

    // максимум запросов в секунду с одного ip
    // выше этого считается ddos
    ddosThreshold = 50

    // окно для подсчёта запросов при ddos детекции
    ddosWindowDuration = time.Second
)

// suspiciousEvent описывает одно подозрительное событие
type suspiciousEvent struct {
    // когда произошло
    at time.Time
    // тип события  auth_failure ddos scan
    kind string
}

// ipRecord хранит историю запросов с одного ip
type ipRecord struct {
    // все события с этого ip
    events []suspiciousEvent
    // когда последний раз логировали ddos с этого ip
    // чтобы не спамить логами каждую миллисекунду
    lastDDOSLog time.Time
   // если true  запись не удаляется автоматически
    suspicious  bool
}

// SecurityMonitor следит за подозрительной активностью
//
// не блокирует запросы  только логирует
// блокировку делает rate limiter  монитор даёт детальную картину
// кто именно пытается нагадить и как
type SecurityMonitor struct {
    mu      sync.Mutex
    records map[string]*ipRecord
    log     *slog.Logger
}

// NewSecurityMonitor создаёт монитор безопасности
func NewSecurityMonitor(log *slog.Logger) *SecurityMonitor {
    m := &SecurityMonitor{
        records: make(map[string]*ipRecord),
        log:     log,
    }
    // чистим старые записи раз в минуту
    // чтобы map не росла вечно
    go m.cleanup()
    return m
}
// cleanup периодически удаляет старые обычные записи из памяти
// подозрительные ip остаются до ручного удаления
func (m *SecurityMonitor) cleanup() {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()
    for range ticker.C {
        m.mu.Lock()
        cutoff := time.Now().Add(-time.Hour)
        for ip, rec := range m.records {
            // если ip помечен как подозрительный  не трогаем
            if rec.suspicious {
                continue
            }
            // обычные записи чистим через час
            fresh := rec.events[:0]
            for _, e := range rec.events {
                if e.at.After(cutoff) {
                    fresh = append(fresh, e)
                }
            }
            if len(fresh) == 0 {
                delete(m.records, ip)
            } else {
                rec.events = fresh
            }
        }
        m.mu.Unlock()
    }
}
// recordEvent добавляет событие для ip и возвращает запись
func (m *SecurityMonitor) recordEvent(ip string, kind string) *ipRecord {
    m.mu.Lock()
    defer m.mu.Unlock()

    rec, ok := m.records[ip]
    if !ok {
        rec = &ipRecord{}
        m.records[ip] = rec
    }
    rec.events = append(rec.events, suspiciousEvent{
        at:   time.Now(),
        kind: kind,
    })
    return rec
}

// countRecent считает события определённого типа за последний период
func countRecent(events []suspiciousEvent, kind string, window time.Duration) int {
    cutoff := time.Now().Add(-window)
    count := 0
    for _, e := range events {
        if e.kind == kind && e.at.After(cutoff) {
            count++
        }
    }
    return count
}

// OnAuthFailure вызывается когда кто то передал неверный токен
//
// логирует предупреждение при каждой попытке
// логирует критическое предупреждение когда попыток слишком много
func (m *SecurityMonitor) OnAuthFailure(ip string, path string) {
    rec := m.recordEvent(ip, "auth_failure")

    m.mu.Lock()
    failures := countRecent(rec.events, "auth_failure", authWindowDuration)
    m.mu.Unlock()

    m.log.Warn("auth failure",
        slog.String("ip", ip),
        slog.String("path", path),
        slog.Int("failures_last_minute", failures),
    )

    // если попыток слишком много  это уже не случайность
    if failures >= maxAuthFailures {
      rec.suspicious = true
        m.log.Error("POSSIBLE BRUTEFORCE DETECTED",
            slog.String("ip", ip),
            slog.String("path", path),
            slog.Int("failures_last_minute", failures),
        )
    }
}

// OnRateLimit вызывается когда ip превысил rate limit
//
// превышение лимита само по себе не страшно
// но если это происходит постоянно  скорее всего ddos
func (m *SecurityMonitor) OnRateLimit(ip string) {
    rec := m.recordEvent(ip, "rate_limit")

    m.mu.Lock()
    hits := countRecent(rec.events, "rate_limit", ddosWindowDuration)
    shouldLog := time.Since(rec.lastDDOSLog) > 5*time.Second
    if shouldLog {
        rec.lastDDOSLog = time.Now()
    }
    m.mu.Unlock()

    // логируем не каждый запрос  а раз в 5 секунд
    // чтобы сам лог не стал проблемой при ddos
    if shouldLog && hits >= ddosThreshold {
      rec.suspicious = true
        m.log.Error("POSSIBLE DDOS DETECTED",
            slog.String("ip", ip),
            slog.Int("rate_limit_hits_per_second", hits),
        )
    }
}

// SecurityMiddleware возвращает gin middleware который следит за атаками
//
// подключается в buildRouter после bearerAuth
// перехватывает 401 и 403 ответы и передаёт их в монитор
func SecurityMiddleware(monitor *SecurityMonitor) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()

        status := c.Writer.Status()
        ip := c.ClientIP()
        path := c.Request.URL.Path

        switch status {
        case http.StatusUnauthorized, http.StatusForbidden:
            monitor.OnAuthFailure(ip, path)
        case http.StatusTooManyRequests:
            monitor.OnRateLimit(ip)
        }
    }
}
func (m *SecurityMonitor) ClearSuspicious(ip string) {
    m.mu.Lock()
    defer m.mu.Unlock()
    if rec, ok := m.records[ip]; ok {
        rec.suspicious = false
        m.log.Info("suspicious ip cleared",
            slog.String("ip", ip),
        )
    }
}

// ListSuspicious возвращает список всех подозрительных ip
// удобно для просмотра кто сейчас в чёрном списке но нам это нужно для другого!!!!!!!!
func (m *SecurityMonitor) ListSuspicious() []string {
    m.mu.Lock()
    defer m.mu.Unlock()
    var list []string
    for ip, rec := range m.records {
        if rec.suspicious {
            list = append(list, ip)
        }
    }
    return list
}
