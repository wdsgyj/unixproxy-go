package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	unixproxy "unixproxy-go"
)

func main() {
	socketPath := flag.String("socket", "/tmp/unixproxy.sock", "unix socket path to listen on")
	flag.Parse()

	server := unixproxy.NewServer(*socketPath)
	server.RegisterTraceListener(unixproxy.TraceListenerFunc(func(event unixproxy.TraceEvent) {
		log.Printf(
			"req=%d method=%s url=%s reused=%t dns=%s connect=%s remote_ip=%s tls=%s request_sent=%s request_bytes=%s first_response_byte=%s response_bytes=%s status=%s error_phase=%s error=%v",
			event.RequestID,
			event.Method,
			event.URL,
			event.ReusedConn,
			formatDuration(event.DNSDuration),
			formatDuration(event.ConnectDuration),
			event.RemoteIP,
			formatTLS(event),
			formatTime(event.RequestSentAt),
			formatInt64(event.RequestBytes),
			formatTime(event.FirstResponseByteAt),
			formatInt64(event.ResponseBytes),
			formatInt(event.StatusCode),
			event.ErrorPhase,
			event.Error,
		)
	}))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		<-sigCh
		if err := server.Close(); err != nil {
			log.Printf("close server: %v", err)
		}
	}()

	log.Printf("listening on unix://%s", *socketPath)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func formatDuration(v *time.Duration) string {
	if v == nil {
		return "-"
	}
	return v.String()
}

func formatTime(v *time.Time) string {
	if v == nil {
		return "-"
	}
	return v.Format(time.RFC3339Nano)
}

func formatInt(v *int) string {
	if v == nil {
		return "-"
	}
	return strconv.Itoa(*v)
}

func formatInt64(v *int64) string {
	if v == nil {
		return "-"
	}
	return strconv.FormatInt(*v, 10)
}

func formatTLS(event unixproxy.TraceEvent) string {
	if event.TLS == nil {
		return "-"
	}
	return event.TLS.VersionName
}
