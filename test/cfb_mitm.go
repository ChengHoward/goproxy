package main

import (
	"crypto/tls"
	"github.com/ChengHoward/goproxy"
	"net/http"
	"sync"
	"time"
)

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
	proxy := goproxy.New(goproxy.WithDecryptHTTPS(&Cache{}))
	server := &http.Server{
		Addr:         ":1087",
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
