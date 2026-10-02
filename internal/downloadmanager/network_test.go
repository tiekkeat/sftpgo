// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only

package downloadmanager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInternalNetworkSwitch(t *testing.T) {
	c := DefaultConfig()
	require.True(t, c.AllowInternalURLs)
	c.AllowedHosts = []string{"public.example"}
	for _, address := range []string{"10.0.0.1", "172.18.0.2", "192.168.1.2", "127.0.0.1", "::1", "fc00::1", "fe80::1", "169.254.169.254", "100.100.100.200", "::ffff:127.0.0.1"} {
		ip := netip.MustParseAddr(address)
		require.NoError(t, c.validateDestination("internal.example", 9000, ip), address)
		_, err := c.validateURL("http://" + netip.AddrPortFrom(ip, 9000).String() + "/file")
		require.NoError(t, err, address)
		blocked := c
		blocked.AllowInternalURLs = false
		require.Error(t, blocked.validateDestination("internal.example", 80, ip), address)
	}
	for _, address := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"} {
		require.Error(t, c.validateDestination("internal.example", 80, netip.MustParseAddr(address)), address)
	}
	public := netip.MustParseAddr("8.8.8.8")
	require.NoError(t, c.validateDestination("public.example", 443, public))
	require.Error(t, c.validateDestination("public.example", 9000, public))
	require.Error(t, c.validateDestination("internal.example", 443, public))
	c.DeniedHosts = []string{"*.internal.example"}
	require.Error(t, c.validateDestination("banned.internal.example", 9000, netip.MustParseAddr("10.0.0.1")))
	_, err := c.validateURL("http://banned.internal.example:9000/file")
	require.Error(t, err)
	for _, raw := range []string{"http://localhost:0/file", "http://localhost:65536/file", "http://[fe80::1%25eth0]/file", "http://user:pass@localhost/file"} {
		_, err := c.validateURL(raw)
		require.Error(t, err, raw)
	}
}

func TestResolvedNetworkPolicy(t *testing.T) {
	c := DefaultConfig()
	private := netip.MustParseAddr("10.0.0.1")
	public := netip.MustParseAddr("8.8.8.8")
	require.NoError(t, c.validateResolvedDestination("internal.example", 9000, []netip.Addr{private}))
	require.Error(t, c.validateResolvedDestination("internal.example", 9000, []netip.Addr{private, public}))
	require.Error(t, c.validateResolvedDestination("internal.example", 9000, []netip.Addr{public, private}))
	require.NoError(t, c.validateResolvedDestination("internal.example", 80, []netip.Addr{public, private}))
	c.AllowInternalURLs = false
	require.Error(t, c.validateResolvedDestination("internal.example", 80, []netip.Addr{public, private}))
	c.AllowInternalURLs = true
	c.AllowedHosts = []string{"public.example"}
	require.Error(t, c.validateResolvedDestination("internal.example", 80, []netip.Addr{public, private}))
	require.NoError(t, c.validateResolvedDestination("internal.example", 9000, []netip.Addr{private}))
}

func TestInternalDownloadAndRedirect(t *testing.T) {
	var contacted atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Add(1)
		_, _ = w.Write([]byte("internal file"))
	}))
	defer source.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(source.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
	}))
	defer redirect.Close()
	c := testConfig()
	c.AllowedHosts = []string{"public.example"}
	var imported []byte
	hooks := testHooks()
	hooks.Import = func(ctx context.Context, r Record, stage string, progress func(int64)) error {
		var err error
		imported, err = os.ReadFile(stage)
		progress(int64(len(imported)))
		return err
	}
	m := testManagerConfig(t, c, hooks)
	job, err := m.Create(Owner{Username: "alice", ID: 1}, "127.0.0.1:1234", redirect.URL, "/file")
	require.NoError(t, err)
	waitFor(t, func() bool { return state(m, job.ID) == "completed" })
	require.Equal(t, "internal file", string(imported))
	require.EqualValues(t, 1, contacted.Load())
	c.AllowInternalURLs = false
	_, err = c.httpClient().Get(source.URL)
	require.Error(t, err)
	_, err = c.httpClient().Get(strings.Replace(source.URL, "127.0.0.1", "localhost", 1))
	require.Error(t, err)
	require.EqualValues(t, 1, contacted.Load())
	// A public redirect cannot bypass disabled internal-address policy.
	req, err := http.NewRequest(http.MethodGet, source.URL, nil)
	require.NoError(t, err)
	require.Error(t, c.httpClient().CheckRedirect(req, []*http.Request{req}))
	// Internal access never disables normal HTTPS certificate verification.
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS source was contacted") }))
	defer tlsServer.Close()
	c.AllowInternalURLs = true
	_, err = c.httpClient().Get(tlsServer.URL)
	require.Error(t, err)
}
