// hmac подпись payload-ов и управление ключами
//
// ротация ключей без даунтайма  основная сложность этого файла
// новый ключ становится активным сразу  старый живёт ещё keyGracePeriod (1h)
// для верификации payload-ов выданных до ротации
// ключи старше keyMaxAge (48h) вытесняются автоматически

package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "sort"
    "sync"
    "time"
)

const (

// keyTTL время жизни ключа с момента создания
    keyTTL         = 24 * time.Hour
//

// keyGracePeriod дополнительное время после истечения ttl
    // в течение которого ключ ещё принимается для верификации
    // нужен чтобы агенты с задержкой в checkin не получали внезапные ошибки подписи

    keyGracePeriod = time.Hour

 // keyMaxAge абсолютный максимум жизни ключа
    // после этого evictStale() его удаляет независимо от grace period

    keyMaxAge      = 48 * time.Hour
)

var (
    ErrKeyNotFound = errors.New("key not found")
    ErrKeyExpired  = errors.New("key expired")
)

// keyEntry одна запись в кольце ключей
//
// validFrom/validUntil позволяют точно контролировать окно верификации
// secret хранится в памяти  никогда не сериализуется и не логируется

type keyEntry struct {
    secret     string
    validFrom  time.Time
    validUntil time.Time
}

// isValid возвращает true если ключ можно использовать для верификации прямо сейчас
// учитывает grace period  ключ валиден ещё keyGracePeriod после validUntil

func (e keyEntry) isValid(now time.Time) bool {
    return !now.Before(e.validFrom) && now.Before(e.validUntil.Add(keyGracePeriod))
}

// isStale возвращает true если ключ пора удалить из памяти
// вызывается только из evictStale() во время Rotate()

func (e keyEntry) isStale(now time.Time) bool {
    return now.Sub(e.validUntil) > keyMaxAge
}

// KeyRing потокобезопасное кольцо hmac ключей
//
// хранит несколько ключей одновременно  текущий для подписи
// и предыдущие для верификации в grace period
// id монотонно растёт  никогда не переиспользуется
//
// RWMutex выбран осознанно  Sign/Verify это читающие операции
// выполняются часто и параллельно  Rotate редко и эксклюзивно

type KeyRing struct {
    mu        sync.RWMutex
    keys      map[int]keyEntry
    currentID int
}

// NewKeyRing создаёт KeyRing с первым ключом ID=1
//
// принимает initialSecret из конфига  не генерирует сам
// генерация случайных секретов  зона ответственности оператора не сервиса

func NewKeyRing(initialSecret string) (*KeyRing, error) {
    if initialSecret == "" {
        return nil, errors.New("keyring: initial secret must not be empty")
    }
    now := time.Now().UTC()
    kr := &KeyRing{
        keys: map[int]keyEntry{
            1: {
                secret:     initialSecret,
                validFrom:  now,
                validUntil: now.Add(keyTTL),
            },
        },
        currentID: 1,
    }
    return kr, nil
}

func (kr *KeyRing) CurrentID() int {
    kr.mu.RLock()
    defer kr.mu.RUnlock()
    return kr.currentID
}

// Sign подписывает payload текущим активным ключом
//
// возвращает подпись и id ключа  агент должен сохранить оба значения
// для последующей верификации через Verify()
//
// payload подписывается как канонический json с отсортированными ключами
// это гарантирует одинаковую подпись независимо от порядка полей

func (kr *KeyRing) Sign(payload map[string]interface{}) (signature string, keyID int, err error) {
    kr.mu.RLock()
    defer kr.mu.RUnlock()

    entry, ok := kr.keys[kr.currentID]
    if !ok {
        return "", 0, fmt.Errorf("keyring: current key %d not found", kr.currentID)
    }
    sig, err := signPayload(payload, entry.secret)
    if err != nil {
        return "", 0, fmt.Errorf("keyring: sign: %w", err)
    }
    return sig, kr.currentID, nil
}

// Rotate добавляет новый ключ и делает его текущим
//
// старый ключ остаётся в кольце  агенты могут верифицировать
// payload-ы подписанные им до истечения grace period
// после Rotate() вызывается evictStale()  старые ключи чистятся сразу
//
// потокобезопасно  берёт write lock только на время записи
// параллельные Sign/Verify не блокируются дольше необходимого

func (kr *KeyRing) Rotate(newSecret string) error {
    if newSecret == "" {
        return errors.New("keyring: new secret must not be empty")
    }

    kr.mu.Lock()
    defer kr.mu.Unlock()

    now := time.Now().UTC()
    newID := kr.currentID + 1
    kr.keys[newID] = keyEntry{
        secret:     newSecret,
        validFrom:  now,
        validUntil: now.Add(keyTTL),
    }
    kr.currentID = newID
    kr.evictStale(now)
    return nil
}

// Verify проверяет подпись payload-а ключом с указанным id
//
// возвращает ошибку если:
// ключ с таким id не найден ErrKeyNotFound слишком старый payload
// ключ найден но просрочен ErrKeyExpired grace period истёк
// подпись не совпадает  payload подделан или повреждён
//
// использует hmac.Equal для сравнения  защита от timing attack

func (kr *KeyRing) Verify(payload map[string]interface{}, signature string, keyID int) error {
    kr.mu.RLock()
    defer kr.mu.RUnlock()

    entry, ok := kr.keys[keyID]
    if !ok {
        return fmt.Errorf("keyring: verify: key %d: %w", keyID, ErrKeyNotFound)
    }
    if !entry.isValid(time.Now().UTC()) {
        return fmt.Errorf("keyring: verify: key %d: %w", keyID, ErrKeyExpired)
    }
    expected, err := signPayload(payload, entry.secret)
    if err != nil {
        return fmt.Errorf("keyring: verify: %w", err)
    }
    if !hmac.Equal([]byte(expected), []byte(signature)) {
        return errors.New("keyring: verify: signature mismatch")
    }
    return nil
}

// evictStale удаляет ключи старше keyMaxAge
//
// вызывается внутри Rotate под write lock  отдельная горутина не нужна
// ротация происходит редко  накладные расходы на итерацию по map незначительны

func (kr *KeyRing) evictStale(now time.Time) {
    for id, entry := range kr.keys {
        if id != kr.currentID && entry.isStale(now) {
            delete(kr.keys, id)
        }
    }
}

// signPayload внутренний хелпер  общий для Sign и Verify
//
// сначала строит канонический json  потом считает hmac-sha256
// вынесен чтобы гарантировать  Sign и Verify всегда используют
// одну и ту же логику сериализации  расхождение здесь самый
// неприятный баг который только может быть в crypto коде

func signPayload(payload map[string]interface{}, secret string) (string, error) {
    canonical, err := canonicalJSON(payload)
    if err != nil {
        return "", fmt.Errorf("canonical json: %w", err)
    }
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(canonical)
    return hex.EncodeToString(mac.Sum(nil)), nil
}

// canonicalJSON сериализует map в json с лексикографически отсортированными ключами
//
// стандартный encoding/json не гарантирует порядок ключей в map
// это задокументированное поведение  для hmac нужен детерминированный
// байтовый поток  поэтому сортируем сами
//
// алгоритм
// 1. marshal в json  чтобы привести значения к json типам
// 2. unmarshal обратно в map  чтобы получить нормализованные значения
// 3. собрать вручную с отсортированными ключами
//
// двойная сериализация не самая дешёвая операция  но payload-ы маленькие
// и вызывается это на каждый checkin  вполне приемлемо

func canonicalJSON(payload interface{}) ([]byte, error) {
    data, err := json.Marshal(payload)
    if err != nil {
        return nil, fmt.Errorf("marshal: %w", err)
    }
    var m map[string]interface{}
    if err := json.Unmarshal(data, &m); err != nil {
        return nil, fmt.Errorf("unmarshal: %w", err)
    }

    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }

    sort.Strings(keys)

    var buf bytes.Buffer
    buf.WriteByte('{')
    for i, k := range keys {
        if i > 0 {
            buf.WriteByte(',')
        }
        keyBytes, err := json.Marshal(k)
        if err != nil {
            return nil, fmt.Errorf("marshal key %q: %w", k, err)
        }
        valBytes, err := json.Marshal(m[k])
        if err != nil {
            return nil, fmt.Errorf("marshal value for key %q: %w", k, err)
        }
        buf.Write(keyBytes)
        buf.WriteByte(':')
        buf.Write(valBytes)
    }
    buf.WriteByte('}')
    return buf.Bytes(), nil
}