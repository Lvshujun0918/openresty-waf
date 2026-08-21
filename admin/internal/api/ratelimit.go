package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// 登录接口 IP 维度限流（与账号维度防爆破互补，防换用户名撞库与 bcrypt CPU 耗尽）：
// 1) 令牌桶限速：单 IP 每 loginRateWindow 内最多 loginRateLimit 次登录请求；
// 2) 失败锁定：loginFailWindow 窗口内失败 ≥ loginFailMax 次，锁定该 IP loginBlockDur。

const (
	loginRateLimit  = 10             // 限速窗口内允许的登录请求数
	loginRateWindow = time.Minute    // 限速窗口
	loginFailMax    = 20             // 失败计数阈值
	loginFailWindow = 10 * time.Minute
	loginBlockDur   = 15 * time.Minute
)

type loginBucket struct {
	tokens       float64
	last         time.Time
	fails        int
	winStart     time.Time
	blockedUntil time.Time
}

// LoginRateLimiter 进程内登录限流器（单实例部署，无需外部存储）。
type LoginRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*loginBucket
	now     func() time.Time // 可注入时钟，便于测试
}

func NewLoginRateLimiter() *LoginRateLimiter {
	return &LoginRateLimiter{
		buckets: make(map[string]*loginBucket),
		now:     time.Now,
	}
}

// Allow 判定该 IP 是否允许发起一次登录请求。
// 返回 retryAfter（需等待时长）与 reason；允许时两者均为零值。
func (l *LoginRateLimiter) Allow(ip string) (retryAfter time.Duration, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked()

	b, ok := l.buckets[ip]
	if !ok {
		b = &loginBucket{tokens: float64(loginRateLimit), last: l.now()}
		l.buckets[ip] = b
	}
	now := l.now()

	// 锁定中：直接拒绝
	if now.Before(b.blockedUntil) {
		return b.blockedUntil.Sub(now), "登录失败次数过多，IP 已被临时封锁"
	}

	// 令牌桶补充
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens += elapsed.Seconds() / loginRateWindow.Seconds() * float64(loginRateLimit)
		if b.tokens > float64(loginRateLimit) {
			b.tokens = float64(loginRateLimit)
		}
		b.last = now
	}

	if b.tokens < 1 {
		wait := time.Duration((1 - b.tokens) / float64(loginRateLimit) * float64(loginRateWindow))
		return wait, "登录请求过于频繁，请稍后再试"
	}
	b.tokens--
	return 0, ""
}

// RecordFailure 记录一次登录失败：窗口内达到阈值即锁定。
func (l *LoginRateLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &loginBucket{tokens: float64(loginRateLimit), last: l.now()}
		l.buckets[ip] = b
	}
	now := l.now()
	// 窗口过期则重新起算
	if b.winStart.IsZero() || now.Sub(b.winStart) > loginFailWindow {
		b.winStart = now
		b.fails = 0
	}
	b.fails++
	if b.fails >= loginFailMax {
		b.blockedUntil = now.Add(loginBlockDur)
		b.fails = 0
	}
}

// RecordSuccess 登录成功：清零该 IP 失败计数。
func (l *LoginRateLimiter) RecordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[ip]; ok {
		b.fails = 0
		b.winStart = time.Time{}
	}
}

// gcLocked 惰性清理：条目过多时剔除长期不活跃且未锁定的桶。
func (l *LoginRateLimiter) gcLocked() {
	if len(l.buckets) <= 1024 {
		return
	}
	now := l.now()
	for ip, b := range l.buckets {
		if now.Sub(b.last) > time.Hour && now.After(b.blockedUntil) {
			delete(l.buckets, ip)
		}
	}
}

// Middleware 登录限流中间件：请求前判定放行，响应后按状态码记账
// （401 记失败、200 清零失败），无需侵入登录处理器。
func (l *LoginRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		retryAfter, reason := l.Allow(ip)
		if reason != "" {
			secs := int(retryAfter.Seconds())
			if secs < 1 {
				secs = 1
			}
			c.Header("Retry-After", fmt.Sprintf("%d", secs))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": reason})
			return
		}
		c.Next()
		switch c.Writer.Status() {
		case http.StatusUnauthorized:
			l.RecordFailure(ip)
		case http.StatusOK:
			l.RecordSuccess(ip)
		}
	}
}
