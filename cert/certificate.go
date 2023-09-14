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
	defaultRootKeyPem = []byte(`-----BEGIN CERTIFICATE-----
MIID/zCCAuegAwIBAgIURUVvCUrd2XpjEnC69lyDtdOpZM8wDQYJKoZIhvcNAQEL
BQAwbDElMCMGA1UEAwwcQ2xvdWRieXBhc3MgTWl0bSAobG9jYWxob3N0KTEmMCQG
A1UECgwdQ2xvdWRieXBhc3MgKGxvY2FsaG9zdCksIEluYy4xCzAJBgNVBAYTAkNO
MQ4wDAYDVQQHDAVXdWhhbjAeFw0yMzA5MTQwMzUyMjNaFw0zMTA5MTIwMzUyMjNa
MHUxCzAJBgNVBAYTAkNOMQ4wDAYDVQQIDAVIdWJlaTEOMAwGA1UEBwwFV3VoYW4x
DzANBgNVBAoMBkRvbmdjZTEOMAwGA1UECwwFV3VoYW4xJTAjBgNVBAMMHENsb3Vk
YnlwYXNzIE1pdG0gKGxvY2FsaG9zdCkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDB0J+qiyPGTXqQ0ABcRqsdMFTdXuBTkjVJ9YvWSin0KPvQcVVKenXx
dGHA/xSkO+jgA06kwMO5KiQu5WK7x7a2Bqx0ILtutlXSUo32V4anTVUnXiIYW/Z8
5PIz3t02Md4/xYJg1Q+KVR7wvhFEh4GXii1C64kxiXwuuKG/sKnNdxgE2N53qhrT
XWWRFiC6ZHZbpb9kpgNxr6OYICI9JJgatCsmjK8SFuULKcKYosR9O52VmtrA9/u5
7uTdJ0qgaQblybwriMKGy8owoNltJ1WagwyLp9E3t3seN5qu4V0E62Ew5sL74t0+
GThS9he0nSGU5NDKWSkCioIreDXjQXCJAgMBAAGjgY8wgYwwHwYDVR0jBBgwFoAU
AlzBnlzw3gVZqByjmVLJnqZyco0wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCA/gw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwGgYDVR0RBBMwEYcEfwAAAYIJbG9jYWxob3N0
MB0GA1UdDgQWBBQtendXc1/EitNs9+TRMcFt6cVJDTANBgkqhkiG9w0BAQsFAAOC
AQEAkPgKzr98KgZDfifdPO0Mw65VsCdbqZQxM6MAh1WTgbO6B50dTD0zcj56bogp
DrkBHCNLh9ynDl4S8H8StI+CbwDlxI/8gAQi0ltNRypA3KZLzCEBh0aeLrrENy5Z
MjSC6fcdGmAGvMgik0fMvOPRTMeMqtQRgQ2Nb/iZrx5SIXimCNUhBKprGlHLvnHG
sVUtCjwIeB6IbEQDtzqvKns7q/KIPoEMXuhMoSAskW7Q/8AIcRNPf77dgR5uNAi1
0SsHuYC5i/28cP7B4nX/PlIsytYcIWYpioMAnTrGIwdFs+x8AmHA7ACuc5eaXdna
EzqgIhsrEXkR5QDfyb3Tehhk4g==
-----END CERTIFICATE-----
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
