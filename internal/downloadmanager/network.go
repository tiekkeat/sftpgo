// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only
package downloadmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
func hostMatches(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix) && host != suffix[1:]
	}
	return host == pattern
}
func (c Config) validateURL(raw string) (*url.URL, error) {
	if len(raw) > 8192 {
		return nil, errors.New("URL is too long")
	}
	u, e := url.Parse(raw)
	if e != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("a direct HTTP/HTTPS URL without credentials or fragment is required")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if strings.Contains(host, "%") {
		return nil, errors.New("invalid source host")
	}
	for _, h := range c.DeniedHosts {
		if hostMatches(host, h) {
			return nil, errors.New("source host is denied")
		}
	}
	if len(c.AllowedHosts) > 0 {
		ok := false
		for _, h := range c.AllowedHosts {
			ok = ok || hostMatches(host, h)
		}
		if !ok {
			return nil, errors.New("source host is not allowed")
		}
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port, e = strconv.Atoi(u.Port())
		if e != nil {
			return nil, errors.New("invalid source port")
		}
	}
	ok := false
	for _, p := range c.AllowedPorts {
		ok = ok || p == port
	}
	if !ok {
		return nil, errors.New("source port is not allowed")
	}
	if ip, e := netip.ParseAddr(host); e == nil && !publicIP(ip) {
		return nil, errors.New("source address is not public")
	}
	return u, nil
}
func displayURL(u *url.URL) string {
	copy := *u
	copy.RawQuery = ""
	copy.ForceQuery = false
	copy.Fragment = ""
	return copy.String()
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c Config) httpClient() *http.Client {
	dialer := net.Dialer{Timeout: time.Duration(c.ConnectTimeout) * time.Second}
	tr := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ResponseHeaderTimeout: time.Duration(c.HeaderTimeout) * time.Second, TLSHandshakeTimeout: time.Duration(c.ConnectTimeout) * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errors.New("invalid source address")
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("source DNS lookup failed")
		}
		for _, ip := range ips {
			if !publicIP(ip) {
				return nil, errors.New("source DNS resolved to a blocked address")
			}
		}
		for _, ip := range ips {
			conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return &idleConn{conn, time.Duration(c.IdleTimeout) * time.Second}, nil
			}
		}
		return nil, errors.New("unable to connect to source")
	}
	return &http.Client{Transport: tr, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > c.MaxRedirects {
			return errors.New("too many redirects")
		}
		_, e := c.validateURL(r.URL.String())
		return e
	}}
}
