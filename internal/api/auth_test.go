package api

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func resetLoginFails() {
	loginFailMu.Lock()
	loginFails = map[string]*loginFailState{}
	loginFailMu.Unlock()
}

// ---- 认证：未登录不得访问面板 ----

func TestUnauthenticatedCannotAccessPanel(t *testing.T) {
	ts, _ := newTestServer(t)

	// 入口根：返回登录页而不是面板本体。
	resp := get(t, ts, entry("/"), nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("入口根应返回 200 登录页，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "访问令牌") {
		t.Fatalf("未登录时应显示登录页，实际内容:\n%s", body)
	}
	if strings.Contains(string(body), "NFT Forward 面板") {
		t.Fatal("未登录不得返回面板本体 HTML")
	}

	// app.js 是面板本体的一部分：未登录必须 404（不泄漏前端指纹）。
	resp2 := get(t, ts, entry("/app.js"), nil)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("未登录访问 app.js 应 404，实际 %d", resp2.StatusCode)
	}

	// 所有 API 一律 401。
	for _, p := range []string{"/api/summary", "/api/live", "/api/rules", "/api/health", "/api/daily", "/api/events"} {
		r := get(t, ts, entry(p), nil)
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("未认证访问 %s 应 401，实际 %d", p, r.StatusCode)
		}
	}
}

// ---- 认证：Bearer / Cookie 有效，query token 无效 ----

func TestBearerTokenAccepted(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := get(t, ts, entry("/api/healthz"), map[string]string{"Authorization": "Bearer " + testToken})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("正确 Bearer 应 200，实际 %d", resp.StatusCode)
	}
}

func TestWrongTokenRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, tok := range []string{
		"", "wrong", strings.Repeat("a", 32),
		testToken + "x", testToken[:31],
	} {
		resp := get(t, ts, entry("/api/healthz"), map[string]string{"Authorization": "Bearer " + tok})
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("错误令牌 %q 应 401，实际 %d", tok, resp.StatusCode)
		}
	}
}

// query string 形式的令牌必须完全无效（避免泄漏进历史/日志/Referer）。
func TestQueryTokenRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{
		"/api/healthz?token=" + testToken,
		"/api/summary?token=" + testToken,
		"/?token=" + testToken,
	} {
		resp := get(t, ts, entry(p), nil)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.HasPrefix(p, "/api/") {
			t.Fatalf("?token= 不应被接受: %s", p)
		}
		if strings.HasPrefix(p, "/api/") && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s 应 401，实际 %d", p, resp.StatusCode)
		}
	}
}

func TestCookieAccepted(t *testing.T) {
	ts, _ := newTestServer(t)
	resp := get(t, ts, entry("/api/healthz"), map[string]string{
		"Cookie": cookieName + "=" + testToken,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("有效 Cookie 应 200，实际 %d", resp.StatusCode)
	}
}

// ---- 登录流程与 Cookie 属性 ----

func TestLoginSetsHttpOnlyLaxCookie(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)
	ts, _ := newTestServer(t)

	resp, err := noRedirectClient().Post(ts.URL+entry("/login"),
		"application/x-www-form-urlencoded", strings.NewReader("token="+testToken))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("登录成功应 302，实际 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != entry("/") {
		t.Fatalf("应重定向到面板入口根，实际 %q", loc)
	}
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			found = c
		}
	}
	if found == nil {
		t.Fatal("未下发会话 Cookie")
	}
	if !found.HttpOnly {
		t.Fatal("Cookie 必须是 HttpOnly（JS 不可读）")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite 应为 Lax（兼顾 iOS Safari），实际 %v", found.SameSite)
	}
	if found.MaxAge != 604800 {
		t.Fatalf("MaxAge 应为 604800（7 天），实际 %d", found.MaxAge)
	}
	if found.Secure {
		t.Fatal("未开启 secure_cookie 时不得设置 Secure（纯 HTTP 会登录失效）")
	}
	if found.Path != entry("/") {
		t.Fatalf("Cookie Path 应覆盖面板入口，实际 %q", found.Path)
	}
	// 令牌绝不能出现在 Location 里。
	if strings.Contains(resp.Header.Get("Location"), testToken) {
		t.Fatal("令牌不得出现在 URL 中")
	}
}

// secure_cookie=true 时才加 Secure。
func TestSecureCookieOptIn(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)
	ts, s := newTestServer(t)
	s.cfg.SecureCookie = true

	resp, err := noRedirectClient().Post(ts.URL+entry("/login"),
		"application/x-www-form-urlencoded", strings.NewReader("token="+testToken))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && !c.Secure {
			t.Fatal("secure_cookie=true 时应设置 Secure")
		}
	}
}

func TestLoginWrongTokenRedirectsWithError(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)
	ts, _ := newTestServer(t)
	resp, err := noRedirectClient().Post(ts.URL+entry("/login"),
		"application/x-www-form-urlencoded", strings.NewReader("token=wrong"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("失败也应 302 回登录页，实际 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=1") {
		t.Fatalf("应带 error 标记，实际 %q", loc)
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.Value != "" {
			t.Fatal("登录失败不得下发会话 Cookie")
		}
	}
}

// 登录体超过 64 KiB 必须 413，绝不截断后继续解析。
func TestLoginBodyTooLarge(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)
	ts, _ := newTestServer(t)

	// 构造一个超大 body，且正确令牌就在前 64 KiB 内 —— 若实现是「截断后解析」，
	// 它会登录成功，这个断言就会失败。
	big := "token=" + testToken + "&pad=" + strings.Repeat("x", 80*1024)
	resp, err := noRedirectClient().Post(ts.URL+entry("/login"),
		"application/x-www-form-urlencoded", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限 body 应 413，实际 %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.Value != "" {
			t.Fatal("超限请求绝不能下发会话 Cookie")
		}
	}
}

// 刚好在限内的 body 正常处理。
func TestLoginBodyWithinLimit(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)
	ts, _ := newTestServer(t)
	form := url.Values{}
	form.Set("token", testToken)
	form.Set("pad", strings.Repeat("y", 1024))
	resp, err := noRedirectClient().Post(ts.URL+entry("/login"),
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("正常 body 应 302 成功，实际 %d", resp.StatusCode)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := noRedirectClient().Post(ts.URL+entry("/logout"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("登出应下发过期 Cookie")
	}
}

// ---- 登录失败节流 ----

func TestLoginThrottleAfterRepeatedFailures(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)

	now := time.Now()
	key := "198.51.100.5"
	for i := 0; i < loginFailBurst; i++ {
		loginRecordFail(key, now)
		if d := loginThrottle(key, now); i+1 < loginFailBurst && d != 0 {
			t.Fatalf("第 %d 次失败后不应节流, got %v", i+1, d)
		}
	}
	if d := loginThrottle(key, now); d != loginFailDelay {
		t.Fatalf("达到阈值后应节流 %v, got %v", loginFailDelay, d)
	}
	// 成功登录立即清零
	loginRecordSuccess(key)
	if d := loginThrottle(key, now); d != 0 {
		t.Fatalf("成功后应清零计数, got %v", d)
	}
}

func TestLoginThrottleWindowExpires(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)

	base := time.Now()
	key := "198.51.100.6"
	for i := 0; i < loginFailBurst+2; i++ {
		loginRecordFail(key, base)
	}
	if d := loginThrottle(key, base); d == 0 {
		t.Fatal("应处于节流状态")
	}
	later := base.Add(loginFailWindow + time.Second)
	if d := loginThrottle(key, later); d != 0 {
		t.Fatalf("超过窗口应恢复, got %v", d)
	}
}

// 成功登录必须零延迟：节流只惩罚失败，不能让手滑几次的用户输对也等 2s。
func TestSuccessfulLoginNotDelayed(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)
	ts, _ := newTestServer(t)
	client := noRedirectClient()

	post := func(tok string) (int, time.Duration) {
		start := time.Now()
		resp, err := client.Post(ts.URL+entry("/login"),
			"application/x-www-form-urlencoded", strings.NewReader("token="+tok))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode, time.Since(start)
	}
	for i := 0; i < loginFailBurst+1; i++ {
		post("wrong")
	}
	code, dur := post(testToken)
	if code != http.StatusFound {
		t.Fatalf("正确 token 应 302, got %d", code)
	}
	if dur >= loginFailDelay {
		t.Errorf("成功登录被节流延迟了 %v（不应超过 %v）", dur, loginFailDelay)
	}
}

// 节流键只能取 RemoteAddr 的 IP，不得信任可伪造的 X-Forwarded-For。
func TestLoginClientKeyIgnoresForwardedFor(t *testing.T) {
	r, err := http.NewRequest("POST", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = "203.0.113.9:44321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")
	if got := loginClientKey(r); got != "203.0.113.9" {
		t.Fatalf("应使用 RemoteAddr 的 IP, got %q", got)
	}
}

// 伪造 XFF 不能绕过节流：同一 RemoteAddr 换头后仍应被节流。
func TestForwardedForCannotBypassThrottle(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)
	ts, _ := newTestServer(t)
	client := noRedirectClient()

	postWithXFF := func(xff string) {
		req, err := http.NewRequest(http.MethodPost, ts.URL+entry("/login"),
			strings.NewReader("token=wrong"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	// 每次换一个 XFF：如果实现信任 XFF，追踪表会有多条、每条都不到阈值。
	for i := 0; i < loginFailBurst; i++ {
		postWithXFF("10.1.1." + string(rune('1'+i)))
	}
	loginFailMu.Lock()
	n := len(loginFails)
	loginFailMu.Unlock()
	if n != 1 {
		t.Fatalf("换 XFF 不应产生多条追踪记录，实际 %d 条（说明信任了 XFF）", n)
	}
}

func TestLoginFailTableBounded(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)

	now := time.Now()
	for i := 0; i < loginFailMaxLen+500; i++ {
		loginRecordFail("10.0."+itoa(i/256)+"."+itoa(i%256), now)
	}
	loginFailMu.Lock()
	n := len(loginFails)
	loginFailMu.Unlock()
	if n > loginFailMaxLen {
		t.Fatalf("追踪表未设上限: %d > %d", n, loginFailMaxLen)
	}
}

// 过期项目会被 GC（不是只靠上限硬截断）。
func TestLoginFailGCRemovesExpired(t *testing.T) {
	resetLoginFails()
	t.Cleanup(resetLoginFails)

	base := time.Now()
	for i := 0; i < 100; i++ {
		loginRecordFail("192.0.2."+itoa(i), base)
	}
	// 时间推进超过窗口后再记一条：GC 应清掉旧的 100 条。
	loginRecordFail("198.51.100.1", base.Add(loginFailWindow+time.Minute))
	loginFailMu.Lock()
	n := len(loginFails)
	loginFailMu.Unlock()
	if n != 1 {
		t.Fatalf("过期项应被 GC，实际剩余 %d 条", n)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// ---- 常量时间比较 ----

func TestTokenEqualConstantTimeSemantics(t *testing.T) {
	if !tokenEqual(testToken, testToken) {
		t.Fatal("相同令牌应相等")
	}
	if tokenEqual(testToken, testToken[:31]) {
		t.Fatal("长度不同必须不相等")
	}
	if tokenEqual("", "") == false {
		// 空对空在 tokenEqual 层面相等；但 authorized() 在 token=="" 时
		// 直接 fail-closed，不会走到这里。
		t.Fatal("等长空串比较应为 true")
	}
	if tokenEqual("a", "b") {
		t.Fatal("等长不同内容应不相等")
	}
}

// authorized 在未配置令牌时必须 fail-closed（全部拒绝，绝不全放行）。
func TestAuthorizedFailsClosedWithoutToken(t *testing.T) {
	ts, s := newTestServer(t)
	s.cfg.Token = ""
	resp := get(t, ts, entry("/api/healthz"), map[string]string{"Authorization": "Bearer " + testToken})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未配置令牌时应一律 401，实际 %d", resp.StatusCode)
	}
}
