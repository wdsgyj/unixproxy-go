package unixproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type TracePhase string

const (
	TracePhasePrepareRequest TracePhase = "prepare_request"
	TracePhaseDNS            TracePhase = "dns"
	TracePhaseConnect        TracePhase = "connect"
	TracePhaseTLSHandshake   TracePhase = "tls_handshake"
	TracePhaseWriteRequest   TracePhase = "write_request"
	TracePhaseFirstResponse  TracePhase = "first_response_byte"
	TracePhaseWriteResponse  TracePhase = "write_response"
)

type TraceEvent struct {
	RequestID uint64
	Method    string
	URL       string

	StartedAt     time.Time
	FinishedAt    time.Time
	TotalDuration time.Duration
	ReusedConn    bool

	DNSDuration     *time.Duration
	ConnectDuration *time.Duration
	RemoteIP        string

	TLSDuration *time.Duration
	TLS         *TLSInfo

	RequestSentAt *time.Time
	RequestBytes  *int64

	FirstResponseByteAt *time.Time
	ResponseBytes       *int64
	StatusCode          *int

	ErrorPhase TracePhase
	Error      error
}

type TLSInfo struct {
	Version                    uint16
	VersionName                string
	CipherSuite                uint16
	CipherSuiteName            string
	ServerName                 string
	NegotiatedProtocol         string
	NegotiatedProtocolIsMutual bool
	DidResume                  bool
	HandshakeComplete          bool
	PeerCertificates           []PeerCertificateInfo
}

type PeerCertificateInfo struct {
	Subject           string
	Issuer            string
	SerialNumber      string
	DNSNames          []string
	EmailAddresses    []string
	IPAddresses       []string
	URIs              []string
	NotBefore         time.Time
	NotAfter          time.Time
	SHA256Fingerprint string
}

type TraceListener interface {
	OnTrace(TraceEvent)
}

type TraceListenerFunc func(TraceEvent)

func (f TraceListenerFunc) OnTrace(event TraceEvent) {
	f(event)
}

type ClientFactory func() *http.Client
type TransportConfigurer func(*http.Transport)
type HTTPClientConfigurer func(*http.Client)

type Option func(*Server)

func WithClientFactory(factory ClientFactory) Option {
	return func(s *Server) {
		if factory != nil {
			s.clientFactory = factory
		}
	}
}

func WithClientTimeout(timeout time.Duration) Option {
	return func(s *Server) {
		s.clientTimeout = timeout
		s.hasClientTimeout = true
	}
}

func WithTransportConfig(configurer TransportConfigurer) Option {
	return func(s *Server) {
		if configurer == nil {
			return
		}
		s.transportConfig = chainTransportConfigurer(s.transportConfig, configurer)
	}
}

func WithClientConfig(configurer HTTPClientConfigurer) Option {
	return func(s *Server) {
		if configurer == nil {
			return
		}
		s.clientConfig = chainHTTPClientConfigurer(s.clientConfig, configurer)
	}
}

type Server struct {
	socketPath    string
	clientFactory ClientFactory
	clientOnce    sync.Once
	clientMu      sync.RWMutex
	client        *http.Client
	clientErr     error

	hasClientTimeout bool
	clientTimeout    time.Duration
	transportConfig  TransportConfigurer
	clientConfig     HTTPClientConfigurer

	listenerMu sync.Mutex
	listener   net.Listener

	closed    chan struct{}
	closeOnce sync.Once

	traceMu        sync.RWMutex
	traceListeners map[uint64]TraceListener
	nextTraceID    uint64
	nextRequestID  atomic.Uint64
}

func NewServer(socketPath string, opts ...Option) *Server {
	s := &Server{
		socketPath:     socketPath,
		closed:         make(chan struct{}),
		traceListeners: make(map[uint64]TraceListener),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *Server) RegisterTraceListener(listener TraceListener) func() {
	if listener == nil {
		return func() {}
	}

	id := atomic.AddUint64(&s.nextTraceID, 1)
	s.traceMu.Lock()
	s.traceListeners[id] = listener
	s.traceMu.Unlock()

	return func() {
		s.traceMu.Lock()
		delete(s.traceListeners, id)
		s.traceMu.Unlock()
	}
}

func (s *Server) ListenAndServe() error {
	if s.socketPath == "" {
		return errors.New("unix socket path is required")
	}

	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on unix socket: %w", err)
	}

	return s.Serve(listener)
}

func (s *Server) Serve(listener net.Listener) error {
	s.listenerMu.Lock()
	if s.listener != nil {
		s.listenerMu.Unlock()
		return errors.New("server already serving")
	}
	s.listener = listener
	s.listenerMu.Unlock()

	defer func() {
		s.listenerMu.Lock()
		if s.listener == listener {
			s.listener = nil
		}
		s.listenerMu.Unlock()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.isClosed() {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				continue
			}
			return fmt.Errorf("accept unix socket connection: %w", err)
		}

		go s.serveConn(conn)
	}
}

func (s *Server) Close() error {
	var closeErr error

	s.closeOnce.Do(func() {
		close(s.closed)

		s.listenerMu.Lock()
		listener := s.listener
		s.listener = nil
		s.listenerMu.Unlock()

		if listener != nil {
			closeErr = listener.Close()
		}

		if s.socketPath != "" {
			if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) && closeErr == nil {
				closeErr = err
			}
		}

		s.clientMu.RLock()
		client := s.client
		s.clientMu.RUnlock()
		if client != nil {
			client.CloseIdleConnections()
		}
	})

	return closeErr
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}

			s.writeErrorResponse(conn, http.StatusBadRequest, err)
			return
		}

		if err := s.handleRequest(conn, req); err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, errUnsupportedMethod) || errors.Is(err, errUnsupportedScheme) || errors.Is(err, errMissingHost) {
				status = http.StatusBadRequest
			}
			s.writeErrorResponse(conn, status, err)
			return
		}

		if req.Close {
			return
		}
	}
}

var (
	errUnsupportedMethod = errors.New("CONNECT is not supported")
	errUnsupportedScheme = errors.New("only http and https are supported")
	errMissingHost       = errors.New("request target host is required")
)

func (s *Server) handleRequest(conn net.Conn, incoming *http.Request) error {
	defer incoming.Body.Close()

	requestID := s.nextRequestID.Add(1)
	trace := newRequestTrace(s, requestID, incoming.Method, traceURLFromRequest(incoming))

	if incoming.Method == http.MethodConnect {
		trace.finishWithError(errUnsupportedMethod, TracePhasePrepareRequest)
		return errUnsupportedMethod
	}

	targetURL, err := normalizeRequestURL(incoming)
	if err != nil {
		trace.finishWithError(err, TracePhasePrepareRequest)
		return err
	}
	trace.setURL(traceURLString(targetURL))

	bodyBytes, err := io.ReadAll(incoming.Body)
	if err != nil {
		wrappedErr := fmt.Errorf("read inbound request body: %w", err)
		trace.finishWithError(wrappedErr, TracePhasePrepareRequest)
		return wrappedErr
	}

	outReq, err := buildOutgoingRequest(incoming, targetURL, trace.context(), bodyBytes)
	if err != nil {
		wrappedErr := fmt.Errorf("build outbound request: %w", err)
		trace.finishWithError(wrappedErr, TracePhasePrepareRequest)
		return wrappedErr
	}

	requestBytes, err := computeRequestBytes(outReq)
	if err != nil {
		wrappedErr := fmt.Errorf("measure outbound request size: %w", err)
		trace.finishWithError(wrappedErr, TracePhasePrepareRequest)
		return wrappedErr
	}
	trace.setPreparedRequestBytes(requestBytes)

	client, err := s.httpClient()
	if err != nil {
		trace.finishWithError(err, TracePhasePrepareRequest)
		return err
	}

	resp, err := client.Do(outReq)
	if err != nil {
		trace.finishWithError(fmt.Errorf("forward request: %w", err), trace.transportFailurePhase())
		return fmt.Errorf("forward request: %w", err)
	}
	defer resp.Body.Close()

	trace.setStatusCode(resp.StatusCode)

	removeHopByHopHeaders(resp.Header)
	resp.Request = nil

	writer := &countingWriter{writer: conn}
	if err := resp.Write(writer); err != nil {
		trace.finishWithError(fmt.Errorf("write response back to unix socket: %w", err), TracePhaseWriteResponse)
		return fmt.Errorf("write response back to unix socket: %w", err)
	}

	trace.finishSuccess(writer.count)
	return nil
}

func buildOutgoingRequest(incoming *http.Request, targetURL *url.URL, ctx context.Context, bodyBytes []byte) (*http.Request, error) {
	var body io.ReadCloser = http.NoBody
	var getBody func() (io.ReadCloser, error)

	if requestHasBody(incoming) || len(bodyBytes) > 0 || incoming.ContentLength > 0 || len(incoming.TransferEncoding) > 0 {
		getBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}

		var err error
		body, err = getBody()
		if err != nil {
			return nil, err
		}
	}

	outReq, err := http.NewRequestWithContext(ctx, incoming.Method, targetURL.String(), body)
	if err != nil {
		return nil, err
	}

	if getBody != nil {
		outReq.GetBody = getBody
	}

	outReq.Header = cloneHeader(incoming.Header)
	removeHopByHopHeaders(outReq.Header)

	outReq.Host = incoming.Host
	outReq.ContentLength = incoming.ContentLength
	outReq.TransferEncoding = append([]string(nil), incoming.TransferEncoding...)
	outReq.Trailer = cloneHeader(incoming.Trailer)
	outReq.Proto = incoming.Proto
	outReq.ProtoMajor = incoming.ProtoMajor
	outReq.ProtoMinor = incoming.ProtoMinor
	outReq.RequestURI = ""

	return outReq, nil
}

func normalizeRequestURL(req *http.Request) (*url.URL, error) {
	if req.URL == nil {
		return nil, errMissingHost
	}

	if req.URL.IsAbs() {
		switch req.URL.Scheme {
		case "http", "https":
			target := new(url.URL)
			*target = *req.URL
			return target, nil
		default:
			return nil, errUnsupportedScheme
		}
	}

	if req.Host == "" {
		return nil, errMissingHost
	}

	scheme := strings.ToLower(strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")))
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return nil, errUnsupportedScheme
	}

	target := new(url.URL)
	*target = *req.URL
	target.Scheme = scheme
	target.Host = req.Host
	return target, nil
}

func (s *Server) buildHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig = cloneTLSConfig(transport.TLSClientConfig)
	if s.transportConfig != nil {
		s.transportConfig(transport)
	}

	client := &http.Client{
		Transport: transport,
	}
	if s.hasClientTimeout {
		client.Timeout = s.clientTimeout
	}
	if s.clientConfig != nil {
		s.clientConfig(client)
	}
	return client
}

func (s *Server) httpClient() (*http.Client, error) {
	s.clientOnce.Do(func() {
		var client *http.Client
		if s.clientFactory != nil {
			client = s.clientFactory()
		} else {
			client = s.buildHTTPClient()
		}
		s.clientMu.Lock()
		defer s.clientMu.Unlock()
		if client == nil {
			s.clientErr = errors.New("client factory returned nil client")
			return
		}
		s.client = client
	})

	s.clientMu.RLock()
	defer s.clientMu.RUnlock()
	if s.clientErr != nil {
		return nil, s.clientErr
	}

	return s.client, nil
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return nil
	}
	return cfg.Clone()
}

func (s *Server) emitTrace(event TraceEvent) {
	s.traceMu.RLock()
	listeners := make([]TraceListener, 0, len(s.traceListeners))
	for _, listener := range s.traceListeners {
		listeners = append(listeners, listener)
	}
	s.traceMu.RUnlock()

	for _, listener := range listeners {
		listener.OnTrace(event)
	}
}

func (s *Server) writeErrorResponse(conn net.Conn, status int, err error) {
	body := err.Error() + "\n"
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}

	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Connection", "close")

	_ = resp.Write(conn)
}

func (s *Server) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

type requestTrace struct {
	server *Server

	mu                sync.Mutex
	event             TraceEvent
	emitted           bool
	dnsStartedAt      time.Time
	connectStartedAt  time.Time
	tlsStartedAt      time.Time
	preparedReqBytes  int64
	pendingErrorPhase TracePhase
}

func newRequestTrace(server *Server, requestID uint64, method string, rawURL string) *requestTrace {
	now := time.Now()
	return &requestTrace{
		server: server,
		event: TraceEvent{
			RequestID: requestID,
			Method:    method,
			URL:       rawURL,
			StartedAt: now,
		},
	}
}

func (t *requestTrace) setURL(rawURL string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.emitted {
		return
	}
	t.event.URL = rawURL
}

func (t *requestTrace) setPreparedRequestBytes(size int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.emitted {
		return
	}
	t.preparedReqBytes = size
}

func (t *requestTrace) setStatusCode(status int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.emitted {
		return
	}
	t.event.StatusCode = intPtr(status)
}

func (t *requestTrace) context() context.Context {
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}

			t.event.ReusedConn = info.Reused
			if info.Reused {
				t.event.DNSDuration = durationPtr(0)
				t.event.ConnectDuration = durationPtr(0)
			}

			if info.Conn != nil {
				if ip := connRemoteIP(info.Conn); ip != "" {
					t.event.RemoteIP = ip
				}
				if state, ok := tlsStateFromConn(info.Conn); ok {
					t.event.TLS = buildTLSInfo(state)
					if info.Reused {
						t.event.TLSDuration = durationPtr(0)
					}
				}
			}
		},
		DNSStart: func(httptrace.DNSStartInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}
			t.dnsStartedAt = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}

			if !t.dnsStartedAt.IsZero() {
				t.event.DNSDuration = durationPtr(time.Since(t.dnsStartedAt))
			} else if t.event.DNSDuration == nil {
				t.event.DNSDuration = durationPtr(0)
			}

			if info.Err != nil && t.pendingErrorPhase == "" {
				t.pendingErrorPhase = TracePhaseDNS
			}
		},
		ConnectStart: func(_, _ string) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}

			if t.event.DNSDuration == nil {
				t.event.DNSDuration = durationPtr(0)
			}
			t.connectStartedAt = time.Now()
		},
		ConnectDone: func(_, addr string, err error) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}

			if !t.connectStartedAt.IsZero() {
				t.event.ConnectDuration = durationPtr(time.Since(t.connectStartedAt))
			}
			if ip := extractIP(addr); ip != "" {
				t.event.RemoteIP = ip
			}
			if err != nil && t.pendingErrorPhase == "" {
				t.pendingErrorPhase = TracePhaseConnect
			}
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}
			t.tlsStartedAt = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}

			if !t.tlsStartedAt.IsZero() {
				t.event.TLSDuration = durationPtr(time.Since(t.tlsStartedAt))
			}
			if state.HandshakeComplete {
				t.event.TLS = buildTLSInfo(state)
			}
			if err != nil && t.pendingErrorPhase == "" {
				t.pendingErrorPhase = TracePhaseTLSHandshake
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}

			if info.Err != nil {
				if t.pendingErrorPhase == "" {
					t.pendingErrorPhase = TracePhaseWriteRequest
				}
				return
			}

			at := time.Now()
			t.event.RequestSentAt = timePtr(at)
			t.event.RequestBytes = int64Ptr(t.preparedReqBytes)
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.emitted {
				return
			}

			at := time.Now()
			t.event.FirstResponseByteAt = timePtr(at)
		},
	}

	return httptrace.WithClientTrace(context.Background(), trace)
}

func (t *requestTrace) transportFailurePhase() TracePhase {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pendingErrorPhase != "" {
		return t.pendingErrorPhase
	}
	if t.event.RequestSentAt != nil {
		return TracePhaseFirstResponse
	}
	return TracePhaseWriteRequest
}

func (t *requestTrace) finishSuccess(responseBytes int64) {
	t.mu.Lock()
	if t.emitted {
		t.mu.Unlock()
		return
	}

	now := time.Now()
	t.event.FinishedAt = now
	t.event.TotalDuration = now.Sub(t.event.StartedAt)
	t.event.ResponseBytes = int64Ptr(responseBytes)

	event := t.event
	t.emitted = true
	t.mu.Unlock()

	t.server.emitTrace(event)
}

func (t *requestTrace) finishWithError(err error, phase TracePhase) {
	t.mu.Lock()
	if t.emitted {
		t.mu.Unlock()
		return
	}

	now := time.Now()
	t.event.FinishedAt = now
	t.event.TotalDuration = now.Sub(t.event.StartedAt)
	t.event.Error = err
	if t.pendingErrorPhase != "" {
		t.event.ErrorPhase = t.pendingErrorPhase
	} else {
		t.event.ErrorPhase = phase
	}

	event := t.event
	t.emitted = true
	t.mu.Unlock()

	t.server.emitTrace(event)
}

type countingWriter struct {
	writer io.Writer
	count  int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if w.writer == nil {
		w.count += int64(len(p))
		return len(p), nil
	}

	n, err := w.writer.Write(p)
	w.count += int64(n)
	return n, err
}

func computeRequestBytes(req *http.Request) (int64, error) {
	cloned := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return 0, err
		}
		cloned.Body = body
		defer cloned.Body.Close()
	}

	writer := &countingWriter{}
	if err := cloned.Write(writer); err != nil {
		return 0, err
	}

	return writer.count, nil
}

func traceURLFromRequest(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	if req.URL.IsAbs() {
		return traceURLString(req.URL)
	}

	target := new(url.URL)
	*target = *req.URL
	target.RawQuery = ""
	target.Fragment = ""
	if req.Host != "" {
		target.Host = req.Host
		scheme := strings.ToLower(strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")))
		if scheme == "" {
			scheme = "https"
		}
		target.Scheme = scheme
	}

	return target.String()
}

func traceURLString(rawURL *url.URL) string {
	if rawURL == nil {
		return ""
	}

	target := new(url.URL)
	*target = *rawURL
	target.RawQuery = ""
	target.ForceQuery = false
	target.Fragment = ""
	return target.String()
}

func requestHasBody(req *http.Request) bool {
	if req == nil {
		return false
	}
	return req.Body != nil && req.Body != http.NoBody
}

func connRemoteIP(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		return extractIP(remoteAddr.String())
	}
	return ""
}

func extractIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func tlsStateFromConn(conn net.Conn) (tls.ConnectionState, bool) {
	type tlsStateProvider interface {
		ConnectionState() tls.ConnectionState
	}

	provider, ok := conn.(tlsStateProvider)
	if !ok {
		return tls.ConnectionState{}, false
	}

	state := provider.ConnectionState()
	if !state.HandshakeComplete {
		return state, false
	}

	return state, true
}

func buildTLSInfo(state tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:                    state.Version,
		VersionName:                tlsVersionName(state.Version),
		CipherSuite:                state.CipherSuite,
		CipherSuiteName:            tls.CipherSuiteName(state.CipherSuite),
		ServerName:                 state.ServerName,
		NegotiatedProtocol:         state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: state.NegotiatedProtocolIsMutual,
		DidResume:                  state.DidResume,
		HandshakeComplete:          state.HandshakeComplete,
		PeerCertificates:           make([]PeerCertificateInfo, 0, len(state.PeerCertificates)),
	}

	for _, cert := range state.PeerCertificates {
		info.PeerCertificates = append(info.PeerCertificates, buildPeerCertificateInfo(cert))
	}

	return info
}

func buildPeerCertificateInfo(cert *x509.Certificate) PeerCertificateInfo {
	uris := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}

	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	fingerprint := sha256.Sum256(cert.Raw)
	return PeerCertificateInfo{
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		SerialNumber:      cert.SerialNumber.String(),
		DNSNames:          append([]string(nil), cert.DNSNames...),
		EmailAddresses:    append([]string(nil), cert.EmailAddresses...),
		IPAddresses:       ips,
		URIs:              uris,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		SHA256Fingerprint: hex.EncodeToString(fingerprint[:]),
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", version)
	}
}

func intPtr(v int) *int {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func durationPtr(v time.Duration) *time.Duration {
	return &v
}

func timePtr(v time.Time) *time.Time {
	return &v
}

func chainTransportConfigurer(current, next TransportConfigurer) TransportConfigurer {
	if current == nil {
		return next
	}
	return func(transport *http.Transport) {
		current(transport)
		next(transport)
	}
}

func chainHTTPClientConfigurer(current, next HTTPClientConfigurer) HTTPClientConfigurer {
	if current == nil {
		return next
	}
	return func(client *http.Client) {
		current(client)
		next(client)
	}
}

func cloneHeader(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
	return dst
}

func removeHopByHopHeaders(header http.Header) {
	if header == nil {
		return
	}

	if connection := header.Get("Connection"); connection != "" {
		for _, field := range strings.Split(connection, ",") {
			if token := textproto.TrimString(field); token != "" {
				header.Del(token)
			}
		}
	}

	for _, field := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(field)
	}
}
