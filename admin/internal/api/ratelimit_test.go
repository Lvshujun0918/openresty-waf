package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newTestLimiter() *LoginRateLimiter {
	l := NewLoginRateLimiter()
	base := time.Now()
	l.now = func() time.Time { return base }
	return l
}

// 令牌桶：窗口内超过限额的请求被拒绝
func TestLoginRateLimiterBurst(t *testing.T) {
	l := newTestLimiter()
	for i := 0; i < loginRateLimit; i++ {
		if _, reason := l.Allow("1.1.1.1"); reason != "" {
			t.Fatalf("第 %d 次请求不应被限流，got: %s", i+1, reason)
		}
	}
	retryAfter, reason := l.Allow("1.1.1.1")
	if reason == "" {
		t.Fatal("超出限额的请求应被限流")
	}
	if retryAfter <= 0 {
		t.Fatalf("应返回正的等待时长，got %v", retryAfter)
	}
	// 其他 IP 不受影响
	if _, reason := l.Allow("2.2.2.2"); reason != "" {
		t.Fatalf("其他 IP 不应被限流，got: %s", reason)
	}
}

// 时间推进后令牌恢复
func TestLoginRateLimiterRefill(t *testing.T) {
	l := newTestLimiter()
	for i := 0; i < loginRateLimit; i++ {
		l.Allow("1.1.1.1")
	}
	if _, reason := l.Allow("1.1.1.1"); reason == "" {
		t.Fatal("耗尽后应被限流")
	}
	// 推进一个完整窗口，令牌应回满
	base := time.Now()
	l.now = func() time.Time { return base.Add(loginRateWindow) }
	if _, reason := l.Allow("1.1.1.1"); reason != "" {
		t.Fatalf("窗口过后应放行，got: %s", reason)
	}
}

// 失败达到阈值锁定 IP；成功清零计数
func TestLoginRateLimiterFailureLockout(t *testing.T) {
	l := newTestLimiter()
	ip := "3.3.3.3"
	for i := 0; i < loginFailMax-1; i++ {
		l.RecordFailure(ip)
	}
	// 未达阈值仍可请求
	if _, reason := l.Allow(ip); reason != "" {
		t.Fatalf("未达失败阈值不应锁定，got: %s", reason)
	}
	l.RecordFailure(ip) // 第 20 次 → 锁定
	retryAfter, reason := l.Allow(ip)
	if reason == "" || retryAfter <= 0 {
		t.Fatal("达到失败阈值后应锁定并返回等待时长")
	}
	// 锁定期间即使令牌充足也拒绝
	if _, reason := l.Allow(ip); reason == "" {
		t.Fatal("锁定期间应持续拒绝")
	}
}

// 成功登录重置失败计数
func TestLoginRateLimiterSuccessResets(t *testing.T) {
	l := newTestLimiter()
	ip := "4.4.4.4"
	for i := 0; i < loginFailMax-1; i++ {
		l.RecordFailure(ip)
	}
	l.RecordSuccess(ip)
	for i := 0; i < loginFailMax-1; i++ {
		l.RecordFailure(ip)
	}
	if _, reason := l.Allow(ip); reason != "" {
		t.Fatalf("成功重置后未达新阈值不应锁定，got: %s", reason)
	}
}

// 中间件端到端：401 记失败、200 清零、429 响应带 Retry-After
func TestLoginRateLimiterMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	l := newTestLimiter()
	r := gin.New()
	r.POST("/login", l.Middleware(), func(c *gin.Context) {
		var req struct {
			Password string `json:"password"`
		}
		_ = c.ShouldBindJSON(&req)
		if req.Password == "right" {
			c.JSON(http.StatusOK, gin.H{"ok": true})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
	})

	post := func(password string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/login", nil)
		if password != "" {
			req = httptest.NewRequest("POST", "/login",
				strings.NewReader(`{"password":"`+password+`"}`))
			req.Header.Set("Content-Type", "application/json")
		}
		r.ServeHTTP(w, req)
		return w
	}

	// 令牌桶 10 次/分钟：前 10 次到达处理器（401），第 11 次被中间件拦截
	for i := 0; i < loginRateLimit; i++ {
		if w := post(""); w.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次应为 401，got %d", i+1, w.Code)
		}
	}
	w := post("")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("超限应为 429，got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 应携带 Retry-After 头")
	}
}
