# unixproxy-go

一个基于 Go 标准库实现的简单 HTTP proxy。

它监听 Unix Domain Socket，接收另一端写入的原始 HTTP request，解析后使用标准库 `http.Client` 将请求真实转发到公网，并把上游返回的 HTTP response 同步写回 Unix Socket。

## 主要功能

- 监听 Unix Socket，接收原始 HTTP/1.1 请求
- 使用标准库 `http.ReadRequest` 解析请求
- 使用标准库 `http.Client` 转发真实请求到 `http` 或 `https` 目标
- 将上游 `http.Response` 原样写回 Unix Socket
- 内置 `http.Client` 复用，不会为每个请求重新创建 client
- 支持注册 trace listener，对每次请求输出一条聚合事件
- trace 事件包含 DNS、TCP、TLS、request 写出、首字节响应、完整响应大小、错误阶段等信息

## 限制

- 不支持 `CONNECT`
- 不做 tunnel，不做代理侧的 HTTPS 握手协商
- 面向 HTTP/1.x 请求
- `ResponseBytes` 统计的是 proxy 成功写回 Unix Socket 的完整响应字节数；无法精确知道对端应用何时从 socket buffer 中完全读完

## 目录结构

- [server.go](/Users/clark/dev/go/home/unixproxy-go/server.go): proxy 核心实现
- [cmd/unixproxy/main.go](/Users/clark/dev/go/home/unixproxy-go/cmd/unixproxy/main.go): 可执行入口
- [server_test.go](/Users/clark/dev/go/home/unixproxy-go/server_test.go): HTTP、HTTPS、连接复用、失败场景测试

## 快速启动

```bash
go run ./cmd/unixproxy -socket /tmp/unixproxy.sock
```

启动后会监听：

```text
unix:///tmp/unixproxy.sock
```

## 请求格式

### 1. absolute-form

推荐直接发送带完整 URL 的请求行：

```http
GET http://example.com/path?q=1 HTTP/1.1
Host: example.com
Connection: close

```

对于 `https` 目标：

```http
GET https://example.com/path?q=1 HTTP/1.1
Host: example.com
Connection: close

```

proxy 会根据 URL 的 scheme 决定使用明文 HTTP 还是 HTTPS。

### 2. origin-form

也支持普通 origin-form，请通过 `Host` 和 `X-Forwarded-Proto` 指定目标：

```http
GET /path?q=1 HTTP/1.1
Host: example.com
X-Forwarded-Proto: https
Connection: close

```

如果未显式传 `X-Forwarded-Proto`，默认按 `https` 处理。

## 使用 Go 通过 Unix Socket 发请求

下面示例直接通过 Unix Socket 给 proxy 发一条 HTTP 请求：

```go
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

func main() {
	conn, err := net.Dial("unix", "/tmp/unixproxy.sock")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	raw := "" +
		"GET https://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: close\r\n" +
		"\r\n"

	if _, err := conn.Write([]byte(raw)); err != nil {
		panic(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println(resp.Status)
}
```

## 作为库使用

### 创建并启动服务

```go
package main

import (
	"log"
	"time"

	unixproxy "unixproxy-go"
)

func main() {
	server := unixproxy.NewServer(
		"/tmp/unixproxy.sock",
		unixproxy.WithClientTimeout(5*time.Second),
	)

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
```

### 注册事件监听

每次请求结束后会回调一次，收到一条聚合事件：

```go
server.RegisterTraceListener(unixproxy.TraceListenerFunc(func(event unixproxy.TraceEvent) {
	log.Printf(
		"url=%s reused=%t dns=%v connect=%v tls=%v request_sent=%v first_response_byte=%v response_bytes=%v status=%v err=%v",
		event.URL,
		event.ReusedConn,
		event.DNSDuration,
		event.ConnectDuration,
		event.TLSDuration,
		event.RequestSentAt,
		event.FirstResponseByteAt,
		event.ResponseBytes,
		event.StatusCode,
		event.Error,
	)
}))
```

## TraceEvent 说明

`TraceEvent` 是“每个请求一条事件”，不是阶段流。

常用字段：

- `RequestID`: 请求 ID
- `Method`: HTTP 方法
- `URL`: 请求 URL，但不包含 query 和 fragment
- `StartedAt`: proxy 开始处理该请求的时间
- `FinishedAt`: 本次请求完成或失败的时间
- `TotalDuration`: 整个请求耗时
- `ReusedConn`: 是否复用了上游连接
- `DNSDuration`: DNS 查询耗时，若复用连接则为 `0`
- `ConnectDuration`: TCP 建连耗时，若复用连接则为 `0`
- `RemoteIP`: 对端 IP
- `TLSDuration`: TLS 握手耗时，若复用 TLS 连接则为 `0`
- `TLS`: TLS 细节，包括版本、cipher suite、协商协议、证书信息等
- `RequestSentAt`: request 全部写给上游的绝对时间
- `RequestBytes`: request 总字节数
- `FirstResponseByteAt`: 收到上游 response 首字节的绝对时间
- `ResponseBytes`: proxy 写回 Unix Socket 的完整响应字节数
- `StatusCode`: 上游响应状态码
- `ErrorPhase`: 失败阶段
- `Error`: 原始错误对象

如果某阶段失败，则后续阶段对应字段保持空值。

## Client 配置

默认情况下，`Server` 会内部创建并复用一个标准库 `http.Client`。

可以通过以下 Option 做常见配置：

- `WithClientTimeout(timeout)`: 设置 `http.Client.Timeout`
- `WithTransportConfig(func(*http.Transport))`: 修改默认 Transport
- `WithClientConfig(func(*http.Client))`: 修改默认 Client

示例：

```go
server := unixproxy.NewServer(
	"/tmp/unixproxy.sock",
	unixproxy.WithClientTimeout(5*time.Second),
	unixproxy.WithTransportConfig(func(tr *http.Transport) {
		tr.MaxIdleConns = 100
		tr.ResponseHeaderTimeout = 2 * time.Second
	}),
	unixproxy.WithClientConfig(func(c *http.Client) {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}),
)
```

如果你希望完全接管内部 client 的创建，可以使用：

```go
server := unixproxy.NewServer(
	"/tmp/unixproxy.sock",
	unixproxy.WithClientFactory(func() *http.Client {
		return &http.Client{
			Timeout: 3 * time.Second,
		}
	}),
)
```

`WithClientFactory` 的优先级高于默认 client 构建逻辑。

## 测试

```bash
go test ./...
```
