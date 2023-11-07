package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/ChengHoward/goproxy"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

var (
	Help   bool
	APIKEY string
	Proxy  string
	Addr   string
)
var checkProxyCompile, _ = regexp.Compile(`^((?:http|socks5):(//)?)?((.*?):(.*?)[@:])?([\w.-]+)(:(\d+))?$`)
var checkAddrCompile, _ = regexp.Compile(`^((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?:)?(\d{1,5})$`)

type Delegate interface {
	// Connect 收到客户端连接
	Connect(ctx *goproxy.Context, rw http.ResponseWriter)
	// Auth 代理身份认证
	Auth(ctx *goproxy.Context, rw http.ResponseWriter)
	// BeforeRequest HTTP请求前 设置X-Forwarded-For, 修改Header、Body
	BeforeRequest(ctx *goproxy.Context)
	// BeforeResponse 响应发送到客户端前, 修改Header、Body、Status Code
	BeforeResponse(ctx *goproxy.Context, resp *http.Response, err error)
	// WebSocketSendMessage websocket发送消息
	WebSocketSendMessage(ctx *goproxy.Context, messageType *int, p *[]byte)
	// WebSockerReceiveMessage websocket接收 消息
	WebSocketReceiveMessage(ctx *goproxy.Context, messageType *int, p *[]byte)
	// ParentProxy 上级代理
	ParentProxy(*http.Request) (*url.URL, error)
	// Finish 本次请求结束
	Finish(ctx *goproxy.Context)
	// 记录错误信息
	ErrorLog(err error)
}

type EventHandler struct{}

func (e *EventHandler) Connect(ctx *goproxy.Context, rw http.ResponseWriter) {
	/*// 保存的数据可以在后面的回调方法中获取
	ctx.Data["req_id"] = "uuid"

	// 禁止访问某个域名
	if strings.Contains(ctx.Req.URL.Host, "example.com") {
		rw.WriteHeader(http.StatusForbidden)
		ctx.Abort()
		return
	}*/
}

func (e *EventHandler) Auth(ctx *goproxy.Context, rw http.ResponseWriter) {
	// 身份验证
}

func (e *EventHandler) BeforeRequest(ctx *goproxy.Context) {
	ctx.Req.Header["x-cb-host"] = []string{ctx.Req.Host}
	ctx.Req.URL.Host = "api.cloudbypass.com"
	ctx.Req.Header["x-cb-apikey"] = []string{APIKEY}
	if !ctx.IsHTTPS() {
		ctx.Req.Header["x-cb-protocol"] = []string{"http"}
		ctx.Req.URL.Scheme = "https"
	}
}

func (e *EventHandler) BeforeResponse(ctx *goproxy.Context, resp *http.Response, err error) {}

// WebSocketSendMessage websocket发送消息
func (h *EventHandler) WebSocketSendMessage(ctx *goproxy.Context, messageType *int, payload *[]byte) {
}

// WebSockerReceiveMessage websocket接收 消息
func (h *EventHandler) WebSocketReceiveMessage(ctx *goproxy.Context, messageType *int, payload *[]byte) {
}

// 设置上级代理
func (e *EventHandler) ParentProxy(req *http.Request) (*url.URL, error) {
	return http.ProxyFromEnvironment(req)
}

func (e *EventHandler) Finish(ctx *goproxy.Context) {
	fmt.Println(ctx.Req.Method, ctx.Req.URL.String())
}

// 记录错误日志
func (e *EventHandler) ErrorLog(err error) {}

// 实现证书缓存接口
type Cache struct {
	m sync.Map
}

func (c *Cache) Set(host string, cert *tls.Certificate) {
	c.m.Store(host, cert)
}
func (c *Cache) Get(host string) *tls.Certificate {
	v, ok := c.m.Load(host)
	if !ok {
		return nil
	}
	return v.(*tls.Certificate)
}
func main() {
	flag.StringVar(&APIKEY, "k", "", "穿云API服务密钥 (APIKEY)")
	flag.StringVar(&Proxy, "x", "", "(可选) 请求标头x-cb-proxy附带")
	flag.StringVar(&Addr, "l", "0.0.0.0:1087", "(可选) 服务监听地址")
	flag.BoolVar(&Help, "h", false, "显示帮助")
	flag.Parse()

	if !Help {
		if APIKEY == "" {
			if len(APIKEY) != 32 {
				fmt.Println("服务密钥无效！")
			}
			Help = true
		}

		if Proxy != "" && checkProxyCompile.FindStringSubmatch(Proxy) == nil {
			fmt.Println("代理格式错误！")
			Help = true
		}

		if Addr != "" && checkAddrCompile.FindStringSubmatch(Addr) == nil {
			fmt.Println("服务监听配置错误！")
			Help = true
		}
	}

	if Help {
		flag.Usage()
		return
	}

	proxy := goproxy.New(goproxy.WithDecryptHTTPS(&Cache{}), goproxy.WithDelegate(&EventHandler{}))
	server := &http.Server{
		Addr:         Addr,
		Handler:      proxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	fmt.Println("Please use proxy " + Addr)
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("服务监听错误！")
	}
}
