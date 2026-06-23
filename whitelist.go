package main

import (
    "log/slog"
    "net"
    "net/http"

    "github.com/gin-gonic/gin"
)

// ipWhitelistEntry одна запись в белом списке
// может быть одиночным ip или подсетью
//
// примеры:
//   192.168.1.1       — одиночный ip
//   192.168.1.0/24    — вся подсеть  256 адресов
//   10.0.0.0/8        — большая корпоративная сеть
type ipWhitelistEntry struct {
    raw  string
    ip   net.IP
    cidr *net.IPNet
}

// IPWhitelist хранит список разрешённых ip и подсетей
//
// если список пустой  пропускает всех
// это намеренно  при первом запуске без настройки сервер работает как раньше
// оператор явно добавляет ip когда готов ограничить доступ
type IPWhitelist struct {
    entries []ipWhitelistEntry
    log     *slog.Logger
}

// NewIPWhitelist создаёт белый список из строк
//
// каждая строка это либо одиночный ip либо подсеть в cidr нотации
// невалидные записи логируются и пропускаются  не паникуем
func NewIPWhitelist(raw []string, log *slog.Logger) *IPWhitelist {
    wl := &IPWhitelist{log: log}

    for _, s := range raw {
        if s == "" {
            continue
        }

        // пробуем распарсить как cidr подсеть
        if _, cidr, err := net.ParseCIDR(s); err == nil {
            wl.entries = append(wl.entries, ipWhitelistEntry{
                raw:  s,
                cidr: cidr,
            })
            continue
        }

        // пробуем как одиночный ip
        if ip := net.ParseIP(s); ip != nil {
            wl.entries = append(wl.entries, ipWhitelistEntry{
                raw: s,
                ip:  ip,
            })
            continue
        }

        // невалидная запись  логируем и идём дальше
        log.Warn("whitelist: invalid entry  skipping",
            slog.String("value", s),
        )
    }

    return wl
}

// allowed возвращает true если ip разрешён
//
// если список пустой  разрешаем всех
// проверяем одиночные ip через Equal
// проверяем подсети через Contains
func (wl *IPWhitelist) allowed(ip net.IP) bool {
    if len(wl.entries) == 0 {
        return true
    }

    for _, entry := range wl.entries {
        if entry.cidr != nil && entry.cidr.Contains(ip) {
            return true
        }
        if entry.ip != nil && entry.ip.Equal(ip) {
            return true
        }
    }

    return false
}

// Middleware возвращает gin middleware который проверяет ip клиента
//
// если ip не в белом списке  возвращает 403 и логирует попытку
// x-forwarded-for заголовок учитывается gin через c.ClientIP()
// убедись что доверяешь своему прокси если используешь его
func (wl *IPWhitelist) Middleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        if len(wl.entries) == 0 {
            c.Next()
            return
        }

        rawIP := c.ClientIP()
        ip := net.ParseIP(rawIP)

        if ip == nil {
            wl.log.Warn("whitelist: cannot parse client ip",
                slog.String("raw", rawIP),
            )
            c.AbortWithStatusJSON(http.StatusForbidden,
                errorResponse("access denied"))
            return
        }

        if !wl.allowed(ip) {
            wl.log.Warn("whitelist: blocked request",
                slog.String("ip", rawIP),
                slog.String("path", c.Request.URL.Path),
                slog.String("method", c.Request.Method),
            )
            c.AbortWithStatusJSON(http.StatusForbidden,
                errorResponse("access denied"))
            return
        }

        c.Next()
    }
}
