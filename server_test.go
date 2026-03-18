package unixproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnixSocketProxyTraceEventForHTTP(t *testing.T) {
	var gotMethod string
	var gotPath string
	var gotBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}

		gotMethod = r.Method
		gotPath = r.URL.RequestURI()
		gotBody = string(body)

		w.Header().Set("X-Upstream", "http")
		_, _ = w.Write([]byte("ok-http"))
	}))
	defer upstream.Close()

	socketPath := newSocketPath(t)
	proxy := NewServer(socketPath)

	var (
		mu     sync.Mutex
		events []TraceEvent
	)
	proxy.RegisterTraceListener(TraceListenerFunc(func(event TraceEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}))

	runServer(t, proxy)

	targetURL := strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1) + "/hello?x=1"
	rawReq := strings.Join([]string{
		fmt.Sprintf("POST %s HTTP/1.1", targetURL),
		strings.TrimPrefix(targetURL, "http://"),
		"Content-Type: text/plain",
		"Content-Length: 5",
		"Connection: close",
		"",
		"hello",
	}, "\r\n")

	resp, body := sendRawRequest(t, socketPath, rawReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if body != "ok-http" {
		t.Fatalf("unexpected response body: %q", body)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("unexpected upstream method: %s", gotMethod)
	}
	if gotPath != "/hello?x=1" {
		t.Fatalf("unexpected upstream path: %s", gotPath)
	}
	if gotBody != "hello" {
		t.Fatalf("unexpected upstream body: %q", gotBody)
	}

	event := waitForSingleEvent(t, &mu, &events)
	if event.URL != strings.Split(targetURL, "?")[0] {
		t.Fatalf("unexpected trace url: %s", event.URL)
	}
	if event.Error != nil {
		t.Fatalf("unexpected trace error: %v", event.Error)
	}
	if event.ErrorPhase != "" {
		t.Fatalf("unexpected error phase: %s", event.ErrorPhase)
	}
	if event.ReusedConn {
		t.Fatalf("did not expect reused connection on first request")
	}
	if event.DNSDuration == nil {
		t.Fatalf("expected dns duration")
	}
	if event.ConnectDuration == nil {
		t.Fatalf("expected connect duration")
	}
	if event.RemoteIP == "" {
		t.Fatalf("expected remote ip")
	}
	if event.TLSDuration != nil {
		t.Fatalf("did not expect tls duration for http request")
	}
	if event.TLS != nil {
		t.Fatalf("did not expect tls info for http request")
	}
	if event.RequestSentAt == nil || event.RequestBytes == nil || *event.RequestBytes <= 0 {
		t.Fatalf("expected request timing and size, got %#v", event)
	}
	if event.FirstResponseByteAt == nil {
		t.Fatalf("expected first response byte timing")
	}
	if event.ResponseBytes == nil || *event.ResponseBytes <= int64(len(body)) {
		t.Fatalf("expected full response size, got %#v", event.ResponseBytes)
	}
	if event.StatusCode == nil || *event.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code in trace: %#v", event.StatusCode)
	}
}

func TestUnixSocketProxyTraceEventForHTTPS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "https")
		_, _ = w.Write([]byte("ok-https"))
	}))
	defer upstream.Close()

	baseTransport := upstream.Client().Transport.(*http.Transport).Clone()
	baseTransport.Proxy = nil
	baseTransport.ForceAttemptHTTP2 = false

	socketPath := newSocketPath(t)
	proxy := NewServer(socketPath, WithClientFactory(func() *http.Client {
		transport := baseTransport.Clone()
		transport.TLSClientConfig = cloneTLSConfig(transport.TLSClientConfig)
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		return &http.Client{Transport: transport}
	}))

	var (
		mu     sync.Mutex
		events []TraceEvent
	)
	proxy.RegisterTraceListener(TraceListenerFunc(func(event TraceEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}))

	runServer(t, proxy)

	targetURL := upstream.URL + "/secure?token=1"
	rawReq := strings.Join([]string{
		fmt.Sprintf("GET %s HTTP/1.1", targetURL),
		strings.TrimPrefix(upstream.URL, "https://"),
		"Connection: close",
		"",
		"",
	}, "\r\n")

	resp, body := sendRawRequest(t, socketPath, rawReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if body != "ok-https" {
		t.Fatalf("unexpected response body: %q", body)
	}

	event := waitForSingleEvent(t, &mu, &events)
	if event.URL != upstream.URL+"/secure" {
		t.Fatalf("unexpected trace url: %s", event.URL)
	}
	if event.Error != nil {
		t.Fatalf("unexpected trace error: %v", event.Error)
	}
	if event.TLSDuration == nil {
		t.Fatalf("expected tls duration")
	}
	if event.TLS == nil {
		t.Fatalf("expected tls info")
	}
	if event.TLS.VersionName == "" {
		t.Fatalf("expected tls version name")
	}
	if len(event.TLS.PeerCertificates) == 0 {
		t.Fatalf("expected peer certificates")
	}
	if event.RemoteIP == "" {
		t.Fatalf("expected remote ip")
	}
	if event.RequestSentAt == nil || event.RequestBytes == nil || *event.RequestBytes <= 0 {
		t.Fatalf("expected request timing and size, got %#v", event)
	}
	if event.FirstResponseByteAt == nil {
		t.Fatalf("expected first response byte timing")
	}
	if event.ResponseBytes == nil || *event.ResponseBytes <= int64(len(body)) {
		t.Fatalf("expected response size, got %#v", event.ResponseBytes)
	}
	if event.StatusCode == nil || *event.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code in trace: %#v", event.StatusCode)
	}
}

func TestUnixSocketProxyPrefersHTTP2WhenUpstreamSupportsIt(t *testing.T) {
	var (
		gotProto string
		gotBody  string
	)

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}

		gotProto = r.Proto
		gotBody = string(body)
		_, _ = w.Write([]byte("ok-h2"))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	socketPath := newSocketPath(t)
	proxy := NewServer(socketPath, WithTransportConfig(func(transport *http.Transport) {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}
	}))

	var (
		mu     sync.Mutex
		events []TraceEvent
	)
	proxy.RegisterTraceListener(TraceListenerFunc(func(event TraceEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}))

	runServer(t, proxy)

	targetURL := upstream.URL + "/secure-h2"
	rawReq := strings.Join([]string{
		fmt.Sprintf("POST %s HTTP/1.1", targetURL),
		strings.TrimPrefix(upstream.URL, "https://"),
		"Content-Type: text/plain",
		"Content-Length: 5",
		"Connection: close",
		"",
		"hello",
	}, "\r\n")

	resp, body := sendRawRequest(t, socketPath, rawReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("expected proxied response HTTP/1.1, got %q", resp.Proto)
	}
	if body != "ok-h2" {
		t.Fatalf("unexpected response body: %q", body)
	}
	if gotProto != "HTTP/2.0" {
		t.Fatalf("expected upstream HTTP/2, got %q", gotProto)
	}
	if gotBody != "hello" {
		t.Fatalf("unexpected upstream body: %q", gotBody)
	}

	event := waitForSingleEvent(t, &mu, &events)
	if event.Error != nil {
		t.Fatalf("unexpected trace error: %v", event.Error)
	}
	if event.TLS == nil {
		t.Fatalf("expected tls info")
	}
	if event.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("expected negotiated protocol h2, got %q", event.TLS.NegotiatedProtocol)
	}
}

func TestUnixSocketProxyRewritesHTTP2StreamingResponseToHTTP11Chunked(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected flusher")
		}

		_, _ = w.Write([]byte("hello "))
		flusher.Flush()
		_, _ = w.Write([]byte("stream"))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()

	socketPath := newSocketPath(t)
	proxy := NewServer(socketPath, WithTransportConfig(func(transport *http.Transport) {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}
	}))

	runServer(t, proxy)

	targetURL := upstream.URL + "/stream"
	rawReq := strings.Join([]string{
		fmt.Sprintf("GET %s HTTP/1.1", targetURL),
		strings.TrimPrefix(upstream.URL, "https://"),
		"Connection: keep-alive",
		"",
		"",
	}, "\r\n")

	resp, body := sendRawRequest(t, socketPath, rawReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("expected proxied response HTTP/1.1, got %q", resp.Proto)
	}
	if len(resp.TransferEncoding) != 1 || resp.TransferEncoding[0] != "chunked" {
		t.Fatalf("expected chunked proxied response, got %#v", resp.TransferEncoding)
	}
	if body != "hello stream" {
		t.Fatalf("unexpected response body: %q", body)
	}
}

func TestBuildOutgoingRequestClearsInboundHTTP11TransportHints(t *testing.T) {
	rawReq := strings.Join([]string{
		"POST /upload HTTP/1.1",
		"Host: example.com",
		"X-Forwarded-Proto: https",
		"Transfer-Encoding: chunked",
		"Trailer: X-Checksum",
		"",
		"5",
		"hello",
		"0",
		"X-Checksum: abc123",
		"",
		"",
	}, "\r\n")

	incoming, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawReq)))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	defer incoming.Body.Close()

	bodyBytes, err := io.ReadAll(incoming.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}

	targetURL, err := normalizeRequestURL(incoming)
	if err != nil {
		t.Fatalf("normalize request url: %v", err)
	}

	outReq, err := buildOutgoingRequest(incoming, targetURL, context.Background(), bodyBytes)
	if err != nil {
		t.Fatalf("build outgoing request: %v", err)
	}
	defer outReq.Body.Close()

	if outReq.Proto != "" || outReq.ProtoMajor != 0 || outReq.ProtoMinor != 0 {
		t.Fatalf("expected outbound proto to be transport-selected, got %q %d.%d", outReq.Proto, outReq.ProtoMajor, outReq.ProtoMinor)
	}
	if len(outReq.TransferEncoding) != 0 {
		t.Fatalf("expected outbound transfer encoding to be cleared, got %#v", outReq.TransferEncoding)
	}
	if outReq.ContentLength != -1 {
		t.Fatalf("expected outbound content length -1 for trailers, got %d", outReq.ContentLength)
	}
	if outReq.Trailer.Get("X-Checksum") != "abc123" {
		t.Fatalf("unexpected outbound trailer: %#v", outReq.Trailer)
	}
	if outReq.Header.Get("Trailer") != "" {
		t.Fatalf("expected Trailer header to be removed from outbound headers, got %#v", outReq.Header)
	}

	outBody, err := io.ReadAll(outReq.Body)
	if err != nil {
		t.Fatalf("read outbound body: %v", err)
	}
	if string(outBody) != "hello" {
		t.Fatalf("unexpected outbound body: %q", outBody)
	}
}

func TestUnixSocketProxyOriginFormUsesForwardedProto(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin-form"))
	}))
	defer upstream.Close()

	socketPath := newSocketPath(t)
	proxy := NewServer(socketPath)

	var (
		mu     sync.Mutex
		events []TraceEvent
	)
	proxy.RegisterTraceListener(TraceListenerFunc(func(event TraceEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}))

	runServer(t, proxy)

	host := strings.TrimPrefix(upstream.URL, "http://")
	rawReq := strings.Join([]string{
		"GET /path HTTP/1.1",
		"Host: " + host,
		"X-Forwarded-Proto: http",
		"Connection: close",
		"",
		"",
	}, "\r\n")

	resp, body := sendRawRequest(t, socketPath, rawReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if body != "origin-form" {
		t.Fatalf("unexpected response body: %q", body)
	}

	event := waitForSingleEvent(t, &mu, &events)
	if event.URL != upstream.URL+"/path" {
		t.Fatalf("unexpected trace url: %s", event.URL)
	}
}

func TestUnixSocketProxyOriginFormDefaultsToHTTPS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin-form-https"))
	}))
	defer upstream.Close()

	baseTransport := upstream.Client().Transport.(*http.Transport).Clone()
	baseTransport.Proxy = nil
	baseTransport.ForceAttemptHTTP2 = false

	socketPath := newSocketPath(t)
	proxy := NewServer(socketPath, WithClientFactory(func() *http.Client {
		transport := baseTransport.Clone()
		transport.TLSClientConfig = cloneTLSConfig(transport.TLSClientConfig)
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		return &http.Client{Transport: transport}
	}))

	var (
		mu     sync.Mutex
		events []TraceEvent
	)
	proxy.RegisterTraceListener(TraceListenerFunc(func(event TraceEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}))

	runServer(t, proxy)

	host := strings.TrimPrefix(upstream.URL, "https://")
	rawReq := strings.Join([]string{
		"GET /path HTTP/1.1",
		"Host: " + host,
		"Connection: close",
		"",
		"",
	}, "\r\n")

	resp, body := sendRawRequest(t, socketPath, rawReq)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if body != "origin-form-https" {
		t.Fatalf("unexpected response body: %q", body)
	}

	event := waitForSingleEvent(t, &mu, &events)
	if event.URL != upstream.URL+"/path" {
		t.Fatalf("unexpected trace url: %s", event.URL)
	}
	if event.TLS == nil {
		t.Fatalf("expected tls info for default https origin-form request")
	}
}

func TestServerReusesHTTPClientAndConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("reuse"))
	}))
	defer upstream.Close()

	var factoryCalls atomic.Int32
	sharedTransport := http.DefaultTransport.(*http.Transport).Clone()
	sharedTransport.Proxy = nil
	sharedTransport.ForceAttemptHTTP2 = false
	sharedClient := &http.Client{Transport: sharedTransport}

	socketPath := newSocketPath(t)
	proxy := NewServer(socketPath, WithClientFactory(func() *http.Client {
		factoryCalls.Add(1)
		return sharedClient
	}))

	var (
		mu     sync.Mutex
		events []TraceEvent
	)
	proxy.RegisterTraceListener(TraceListenerFunc(func(event TraceEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}))

	runServer(t, proxy)

	sendOnce := func() {
		rawReq := strings.Join([]string{
			fmt.Sprintf("GET %s HTTP/1.1", upstream.URL),
			strings.TrimPrefix(upstream.URL, "http://"),
			"Connection: close",
			"",
			"",
		}, "\r\n")

		resp, body := sendRawRequest(t, socketPath, rawReq)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}
		if body != "reuse" {
			t.Fatalf("unexpected body: %q", body)
		}
	}

	sendOnce()
	sendOnce()

	waitForEventCount(t, &mu, &events, 2)

	if got := factoryCalls.Load(); got != 1 {
		t.Fatalf("client factory called %d times, want 1", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if !events[1].ReusedConn {
		t.Fatalf("expected second request to reuse upstream connection, got %#v", events[1])
	}
	if events[1].DNSDuration == nil || *events[1].DNSDuration != 0 {
		t.Fatalf("expected reused dns duration to be 0, got %#v", events[1].DNSDuration)
	}
	if events[1].ConnectDuration == nil || *events[1].ConnectDuration != 0 {
		t.Fatalf("expected reused connect duration to be 0, got %#v", events[1].ConnectDuration)
	}
	if events[1].RequestSentAt == nil || events[1].ResponseBytes == nil {
		t.Fatalf("expected request/response stats on reused event, got %#v", events[1])
	}
}

func TestServerBuildsDefaultClientWithOptions(t *testing.T) {
	redirectHookCalled := false
	proxy := NewServer(
		newSocketPath(t),
		WithClientTimeout(3*time.Second),
		WithTransportConfig(func(transport *http.Transport) {
			transport.MaxIdleConns = 23
			transport.ResponseHeaderTimeout = 150 * time.Millisecond
		}),
		WithClientConfig(func(client *http.Client) {
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				redirectHookCalled = true
				return http.ErrUseLastResponse
			}
		}),
	)

	client, err := proxy.httpClient()
	if err != nil {
		t.Fatalf("build http client: %v", err)
	}
	if client.Timeout != 3*time.Second {
		t.Fatalf("unexpected client timeout: %s", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", client.Transport)
	}
	if transport.MaxIdleConns != 23 {
		t.Fatalf("unexpected max idle conns: %d", transport.MaxIdleConns)
	}
	if transport.ResponseHeaderTimeout != 150*time.Millisecond {
		t.Fatalf("unexpected response header timeout: %s", transport.ResponseHeaderTimeout)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatalf("expected transport to prefer http2")
	}
	if client.CheckRedirect == nil {
		t.Fatalf("expected custom redirect hook")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("unexpected redirect hook error: %v", err)
	}
	if !redirectHookCalled {
		t.Fatalf("expected redirect hook to be installed")
	}
}

func TestUnixSocketProxyTraceEventOnConnectError(t *testing.T) {
	socketPath := newSocketPath(t)
	proxy := NewServer(socketPath)

	var (
		mu     sync.Mutex
		events []TraceEvent
	)
	proxy.RegisterTraceListener(TraceListenerFunc(func(event TraceEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}))

	runServer(t, proxy)

	targetURL := "http://127.0.0.1:1/fail?x=1"
	rawReq := strings.Join([]string{
		fmt.Sprintf("GET %s HTTP/1.1", targetURL),
		"127.0.0.1:1",
		"Connection: close",
		"",
		"",
	}, "\r\n")

	resp, _ := sendRawRequest(t, socketPath, rawReq)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	event := waitForSingleEvent(t, &mu, &events)
	if event.URL != "http://127.0.0.1:1/fail" {
		t.Fatalf("unexpected trace url: %s", event.URL)
	}
	if event.Error == nil {
		t.Fatalf("expected trace error")
	}
	if event.ErrorPhase == "" {
		t.Fatalf("expected error phase")
	}
	if event.DNSDuration == nil || *event.DNSDuration != 0 {
		t.Fatalf("expected dns duration 0 for ip literal, got %#v", event.DNSDuration)
	}
	if event.ConnectDuration == nil {
		t.Fatalf("expected connect duration")
	}
	if event.RemoteIP != "127.0.0.1" {
		t.Fatalf("unexpected remote ip: %s", event.RemoteIP)
	}
	switch event.ErrorPhase {
	case TracePhaseConnect, TracePhaseWriteRequest:
		if event.FirstResponseByteAt != nil {
			t.Fatalf("did not expect first response byte timing after %s", event.ErrorPhase)
		}
	case TracePhaseFirstResponse:
		if event.RequestSentAt == nil {
			t.Fatalf("expected request sent timing before first response failure")
		}
	default:
		t.Fatalf("unexpected error phase: %s", event.ErrorPhase)
	}
	if event.ResponseBytes != nil {
		t.Fatalf("did not expect response size after connect error")
	}
}

func runServer(t *testing.T, proxy *Server) {
	t.Helper()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.ListenAndServe()
	}()

	t.Cleanup(func() {
		if err := proxy.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close proxy: %v", err)
		}
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("proxy serve returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for proxy shutdown")
		}
	})

	waitForDial(t, proxy.socketPath)
}

func waitForDial(t *testing.T, socketPath string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("proxy socket did not become ready: %s", socketPath)
}

func sendRawRequest(t *testing.T, socketPath string, rawReq string) (*http.Response, string) {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial proxy socket: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, rawReq); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read proxied response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxied response body: %v", err)
	}

	return resp, string(body)
}

func waitForSingleEvent(t *testing.T, mu *sync.Mutex, events *[]TraceEvent) TraceEvent {
	t.Helper()

	waitForEventCount(t, mu, events, 1)

	mu.Lock()
	defer mu.Unlock()
	return (*events)[0]
}

func waitForEventCount(t *testing.T, mu *sync.Mutex, events *[]TraceEvent, count int) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		current := len(*events)
		mu.Unlock()
		if current >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %d trace events", count)
}

func newSocketPath(t *testing.T) string {
	t.Helper()

	return filepath.Join(
		"/tmp",
		fmt.Sprintf("uxp-%d.sock", time.Now().UnixNano()),
	)
}
