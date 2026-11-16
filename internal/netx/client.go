// Package netx is the shared HTTP client for recon.
//
// It is deliberately small: one client, one token-bucket limiter, a redirect
// policy that refuses to leave scope, and a body cap so a single huge response
// cannot exhaust memory.
package netx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Response is the normalized result of a GET.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	FinalURL   string
	TLS        *tls.ConnectionState
	Truncated  bool
}

// Session is credential material attached to in-scope requests only. It is
// never written into a pack unless the operator explicitly asks for it.
type Session struct {
	Cookies string
	Headers map[string]string
	// Hosts limits where the credentials may be sent. Subdomains of each
	// entry are allowed. An empty list means "all hosts" (used by callers
	// that already enforce scope themselves).
	Hosts []string
}

// Client wraps http.Client with a scope-aware redirect policy and rate limit.
type Client struct {
	HTTP *http.Client
	UA   string
	lim  *Limiter
	sess *Session
}

// SetSession attaches cookies and headers to every in-scope request.
func (c *Client) SetSession(s Session) { c.sess = &s }

// New builds a client. allow is consulted for every redirect target; return
// false to stop following. Pass nil to follow redirects unconditionally.
func New(ua string, rps int, allow func(*url.URL) bool) *Client {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// Recon records the certificate rather than trusting it: an expired or
		// mismatched certificate is itself worth reporting.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			if allow != nil && !allow(req.URL) {
				return fmt.Errorf("redirect out of scope: %s", req.URL.Host)
			}
			return nil
		},
	}
	return &Client{HTTP: hc, UA: ua, lim: NewLimiter(rps)}
}

// Get fetches raw, reading at most max bytes of body.
func (c *Client) Get(ctx context.Context, raw string, max int64) (*Response, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	if c.sess != nil && sessionAllowed(c.sess.Hosts, u.Hostname()) {
		if c.sess.Cookies != "" && req.Header.Get("Cookie") == "" {
			req.Header.Set("Cookie", c.sess.Cookies)
		}
		for k, v := range c.sess.Headers {
			if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
				continue
			}
			req.Header.Set(k, v)
		}
	}

	if !c.lim.Wait(ctx) {
		return nil, ctx.Err()
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil && len(b) == 0 {
		return nil, err
	}
	truncated := int64(len(b)) > max
	if truncated {
		b = b[:max]
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       b,
		FinalURL:   resp.Request.URL.String(),
		TLS:        resp.TLS,
		Truncated:  truncated,
	}, nil
}

// PostJSON posts a JSON body and returns the raw response. Used by the public
// program-directory APIs; session credentials are never attached here.
func (c *Client) PostJSON(ctx context.Context, raw string, payload any, max int64, headers map[string]string) (int, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UA)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if !c.lim.Wait(ctx) {
		return 0, nil, ctx.Err()
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil && len(b) == 0 {
		return resp.StatusCode, nil, err
	}
	if int64(len(b)) > max {
		b = b[:max]
	}
	return resp.StatusCode, b, nil
}

// sessionAllowed implements the host allow-list for credentials.
func sessionAllowed(hosts []string, host string) bool {
	if len(hosts) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h == "" {
			continue
		}
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// Close releases idle connections and stops the limiter goroutine.
func (c *Client) Close() {
	c.HTTP.CloseIdleConnections()
	c.lim.Close()
}

// Limiter is a token bucket that refills at a fixed rate.
type Limiter struct {
	tokens chan struct{}
	done   chan struct{}
	once   chan struct{}
}

// NewLimiter allows rps requests per second across the process. rps <= 0
// disables limiting.
func NewLimiter(rps int) *Limiter {
	l := &Limiter{tokens: make(chan struct{}, 1), done: make(chan struct{}), once: make(chan struct{})}
	if rps <= 0 {
		close(l.once)
		return l
	}
	interval := time.Second / time.Duration(rps)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case l.tokens <- struct{}{}:
				default:
				}
			case <-l.done:
				return
			}
		}
	}()
	return l
}

// Wait blocks until a token is available or ctx is done.
func (l *Limiter) Wait(ctx context.Context) bool {
	select {
	case <-l.once:
		return true
	default:
	}
	select {
	case <-l.tokens:
		return true
	case <-ctx.Done():
		return false
	}
}

// Close stops the refill goroutine. Safe to call once.
func (l *Limiter) Close() {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
}
