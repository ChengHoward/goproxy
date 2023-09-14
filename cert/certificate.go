// Copyright 2018 ouqiang authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package cert 证书管理
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"fmt"
	"hash/fnv"
	"math/rand"
	"strings"

	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

var (
	defaultRootCAPem = []byte(`-----BEGIN CERTIFICATE-----
MIIDuTCCAqGgAwIBAgIUJt9lvPuk/Up6Y74Tu+UpFO2NoGQwDQYJKoZIhvcNAQEL
BQAwbDElMCMGA1UEAwwcQ2xvdWRieXBhc3MgTWl0bSAobG9jYWxob3N0KTEmMCQG
A1UECgwdQ2xvdWRieXBhc3MgKGxvY2FsaG9zdCksIEluYy4xCzAJBgNVBAYTAkNO
MQ4wDAYDVQQHDAVXdWhhbjAeFw0yMzA5MTQwMzUyMjNaFw0zMTA5MTIwMzUyMjNa
MGwxJTAjBgNVBAMMHENsb3VkYnlwYXNzIE1pdG0gKGxvY2FsaG9zdCkxJjAkBgNV
BAoMHUNsb3VkYnlwYXNzIChsb2NhbGhvc3QpLCBJbmMuMQswCQYDVQQGEwJDTjEO
MAwGA1UEBwwFV3VoYW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDm
D/1wGbCHlbK85K//JUm67dgRRB5jyVV4UqUMdZBS4HF9RNlXzJ+uWVvAHYhniVkV
u6c/n3Ue0HNDFg5jVXviOkeaHpFiY2+g83JqEh0mXKTXg1oVNt7gkKIKpjNTyRxe
iaObNeKl247Q6JAl/tPc7a+3QAIgAEsfQvhEIi+mg8DWoEryFl+CMGsC/QMxkoyO
Ki6F8L9J0O726r3MlXhVMvMqXHdU8hi6bC2txr509pGuuHHKdrGbouxSySSFjDWX
8YuC78dhP80x8myqQjQ7Xv4+ef4xfvbCMZ9B+z/QKJZJVeKFwvVyNyoOpR0MYxTr
2lvRWQgpqeq2CKRhL04DAgMBAAGjUzBRMB0GA1UdDgQWBBQCXMGeXPDeBVmoHKOZ
UsmepnJyjTAfBgNVHSMEGDAWgBQCXMGeXPDeBVmoHKOZUsmepnJyjTAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBh2Ru9NaTUAGC0r/xQJaIaWmsA
vDCjc0vuAO5CZXIU7T+cxkkAaRCZ7a13Z97nesui4AjarPXVGzQ8kL6ZuPqaNRf7
ZlVwpXQBf0F9S8kc2wDbAA41Ahg/Wa/6Y7iINZGTw9zXWPEfkfvcOKRDTNNibMGB
zaHsTC2opiO6d6/9iHHl0MT2WpWvtsbvpU6VRrBUQSVU0h6dBJvy58St/nevd7NA
oB4KA3VRUzCBREf6VFSjep/1U1JDwwGzHgQ7+cAMq784FLF0Rlalg7VipWuGjZof
A9PSWqEVqz/pZWk61QZ/IN/eAgepp+P3o9Ie0rsjInI0+aFpBTRyewLr/hpY
-----END CERTIFICATE-----
`)
	defaultRootKeyPem = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDmD/1wGbCHlbK8
5K//JUm67dgRRB5jyVV4UqUMdZBS4HF9RNlXzJ+uWVvAHYhniVkVu6c/n3Ue0HND
Fg5jVXviOkeaHpFiY2+g83JqEh0mXKTXg1oVNt7gkKIKpjNTyRxeiaObNeKl247Q
6JAl/tPc7a+3QAIgAEsfQvhEIi+mg8DWoEryFl+CMGsC/QMxkoyOKi6F8L9J0O72
6r3MlXhVMvMqXHdU8hi6bC2txr509pGuuHHKdrGbouxSySSFjDWX8YuC78dhP80x
8myqQjQ7Xv4+ef4xfvbCMZ9B+z/QKJZJVeKFwvVyNyoOpR0MYxTr2lvRWQgpqeq2
CKRhL04DAgMBAAECggEABejgkxMAhzKMsNaL0gPlDxdk+xL2NfMOTBCvJK7KBX1h
ICGU46y/zmL8tF4e6HsE29+oitdxwfGtoigPr58jUv45lwhwYgOwrmKJ/7iX7gfO
ZlV9cQgyu5W/y09NXW2c0Xp3G9EHVfNZ3wNi3Vb+rwZq8aFQ5B/zI2PFzm+TcLVi
kGTTCBX9xd/U7vmXIvXq3X0nSKoZ30msjFD53wmn44dMgGSqKdPBWh08v8B5aohk
F6wMOyKqZqVdCSfpACVfVNzpJ/gt7sxXL9sJVU6W8YBzR/h9+lfH5Q5EP44dB3Id
gwjk1n0ye5brX3BBiVa3S+nznwAPgfNzoUS9cpduoQKBgQDqRNefD5M3Lr4cnGcr
/d+k/p9tRuwN+4Z47+QzuCvVSzgKF4+crgdQhjVzVolamsB2q1kdRkdHt+kSLw6s
fZFVSqO88HspiQrTvm8h/7cvBAx1pkxsHTEx72m2d3JVcHs4Ik+McElgqgg5YkyU
gAhBJp6U/Mbbd1wJjnDn0v8lJwKBgQD7Z0HtCK1+hI2oKO237ytOsRM2xWW2AFba
qCWsqvhg12ojT7Fq61wV2/ILdH51mkVmTqebcWpigzWU8OU/Ndj5RBo+PO7AYzH/
BHhIoH+BnQk4Mss4rcQfP0BPeUalpUWIWoYh8p2lSdCx00AYTZ/KFZQWP0Tod59j
8c5Z/vLxxQKBgQDMmJsHm36irvvx2NZyISJ04rsxoML/4y+p5ziRwsLlYO/sQG94
ErToqo170ZPbwVNdUIBfhMUz6XZwHxDdrDyFFM6zcALgX4NJMgO02bOOKCcJiNct
hME2LzVP2jnMTJQQjkaTDG3JMjZEh4kCGF8dJzFQRQMXIMMMxY3tqOST+QKBgQC5
sRhB03IKjC/xsGF9xZuwYRy3DPDGkNOWaDKDqjkRlqsf7+I0/ikjQDU0/tPVW6C9
I4WrTAdvQkkWfSRnHwfnfcUAiZMz6VDpc0zBIENt4icIKoRulfLRva9rxEFJYpzM
TUjb1E9a4f3TCx1BljxbULrz/8GPD6RcdyOa17RsnQKBgQDoGJIXSxlUMlpqU3zB
ZsHSzqQBf6CflDKoXIHIdt/dFcZR+DSvWUQxb1vB7QNdsdapQMImZHcpkQN2eXhU
craYLoWmD88YGV2djUxC+k99zK/T7GXoXARlZBB1n5Tnoi18swZ8cWp99zEvj+ea
INsqK+5x5ooXv6M+U12fiuVNyg==
-----END PRIVATE KEY-----
`)
)

var (
	defaultRootCA  *x509.Certificate
	defaultRootKey *ecdsa.PrivateKey
)

func init() {
	var err error
	block, _ := pem.Decode(defaultRootCAPem)
	defaultRootCA, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("加载根证书失败: %s", err))
	}
	block, _ = pem.Decode(defaultRootKeyPem)
	defaultRootKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("加载根证书私钥失败: %s", err))
	}
}

// Certificate 证书管理
type Certificate struct {
	cache             Cache
	defaultPrivateKey *ecdsa.PrivateKey
}

type Pair struct {
	Cert            *x509.Certificate
	CertBytes       []byte
	PrivateKey      *ecdsa.PrivateKey
	PrivateKeyBytes []byte
}

func NewCertificate(cache Cache, useDefaultPrivateKey ...bool) *Certificate {
	c := &Certificate{
		cache: cache,
	}
	if len(useDefaultPrivateKey) > 0 && useDefaultPrivateKey[0] {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		if err != nil {
			panic(err)
		}
		c.defaultPrivateKey = priv
	}

	return c
}

// GenerateTlsConfig 生成TLS配置
func (c *Certificate) GenerateTlsConfig(host string) (*tls.Config, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if c.cache != nil {
		fields := strings.Split(host, ".")
		sudDomains := []string{host, strings.Join(fields[1:], ".")}
		for _, item := range sudDomains {
			// 先从缓存中查找证书
			if cert := c.cache.Get(item); cert != nil {
				tlsConf := &tls.Config{
					Certificates: []tls.Certificate{*cert},
				}

				return tlsConf, nil
			}
		}
	}
	pair, err := c.GeneratePem(host, 1, defaultRootCA, defaultRootKey)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(pair.CertBytes, pair.PrivateKeyBytes)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if c.cache != nil {
		// 缓存证书
		if len(pair.Cert.IPAddresses) > 0 {
			c.cache.Set(host, &cert)
		}
		for _, item := range pair.Cert.DNSNames {
			item = strings.TrimPrefix(item, "*.")
			c.cache.Set(item, &cert)
		}

	}

	return tlsConf, nil
}

// GeneratePem 生成证书
func (c *Certificate) GeneratePem(host string, expireDays int, rootCA *x509.Certificate, rootKey *ecdsa.PrivateKey) (*Pair, error) {
	var priv *ecdsa.PrivateKey
	var err error

	if c.defaultPrivateKey != nil {
		priv = c.defaultPrivateKey
	} else {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	}
	if err != nil {
		return nil, err
	}
	tmpl := c.template(host, expireDays)
	derBytes, err := x509.CreateCertificate(crand.Reader, tmpl, rootCA, &priv.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	serverCert := pem.EncodeToMemory(certBlock)
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}
	serverKey := pem.EncodeToMemory(keyBlock)

	p := &Pair{
		Cert:            tmpl,
		CertBytes:       serverCert,
		PrivateKey:      priv,
		PrivateKeyBytes: serverKey,
	}

	return p, nil
}

// GenerateCA 生成根证书
func (c *Certificate) GenerateCA() (*Pair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject: pkix.Name{
			CommonName:   "Mars",
			Country:      []string{"China"},
			Organization: []string{"Goproxy"},
			Province:     []string{"FuJian"},
			Locality:     []string{"Xiamen"},
		},
		NotBefore:             time.Now().AddDate(0, -1, 0),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		EmailAddresses:        []string{"qingqianludao@gmail.com"},
	}

	derBytes, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	serverCert := pem.EncodeToMemory(certBlock)

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}
	serverKey := pem.EncodeToMemory(keyBlock)

	p := &Pair{
		Cert:            tmpl,
		CertBytes:       serverCert,
		PrivateKey:      priv,
		PrivateKeyBytes: serverKey,
	}

	return p, nil
}

func (c *Certificate) template(host string, expireYears int) *x509.Certificate {
	fv := fnv.New32a()
	_, _ = fv.Write([]byte(host))

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(fv.Sum32())),
		Subject: pkix.Name{
			CommonName:   host,
			Country:      []string{"China"},
			Organization: []string{"Goproxy"},
			Province:     []string{"FuJian"},
			Locality:     []string{"Xiamen"},
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(expireYears, 0, 0),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment,
		EmailAddresses:        []string{"qingqianludao@gmail.com"},
	}
	hosts := strings.Split(host, ",")
	for _, item := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
			continue
		}

		fields := strings.Split(item, ".")
		fieldNum := len(fields)
		for i := 0; i <= (fieldNum - 2); i++ {
			cert.DNSNames = append(cert.DNSNames, "*."+strings.Join(fields[i:], "."))
		}
		if fieldNum == 2 {
			cert.DNSNames = append(cert.DNSNames, item)
		}
	}

	return cert
}

// DefaultRootCAPem 根证书
func DefaultRootCAPem() []byte {
	return defaultRootCAPem
}
