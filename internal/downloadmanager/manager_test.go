// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only

package downloadmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testConfig() Config {
	c := DefaultConfig()
	c.Enabled = true
	c.MaxFileSize = 1 << 20
	c.MaxStagingSize = 4 << 20
	c.MaxStagingPerUser = 2 << 20
	c.MinFreeSpace = 0
	c.RetryMax = 0
	return c
}
func testHooks() Hooks {
	return Hooks{Check: func(Record) (Policy, error) { return Policy{Access: "enabled"}, nil }, Import: func(ctx context.Context, r Record, p string, progress func(int64)) error {
		data, e := os.ReadFile(p)
		progress(int64(len(data)))
		return e
	}}
}
func testManager(t *testing.T, h Hooks) *Manager { return testManagerConfig(t, testConfig(), h) }
func testManagerConfig(t *testing.T, c Config, h Hooks) *Manager {
	t.Helper()
	k := kms.Configuration{}
	require.NoError(t, k.Initialize())
	m, e := Open(c, t.TempDir(), h)
	require.NoError(t, e)
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	return m
}
func response(r *http.Request, status int, body string, total int64) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), ContentLength: total, Header: http.Header{"Etag": []string{`"version1"`}}, Request: r}
}
func enqueue(t *testing.T, m *Manager, user string) Job {
	t.Helper()
	j, e := m.Create(Owner{Username: user, ID: 1, CreatedAt: 2}, "203.0.113.5:1234", "https://example.com/file?signature=secret", "/file")
	require.NoError(t, e)
	return j
}
func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	require.Eventually(t, f, 5*time.Second, 10*time.Millisecond)
}
func state(m *Manager, id string) string {
	r, e := m.Get(id, nil)
	if e != nil {
		return ""
	}
	return r.Job.State
}
func noWorker(m *Manager, id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running[id] == nil
}

func TestPublicNetworkPolicy(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "192.0.2.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "64:ff9b::a00:1", "2002:7f00:1::", "2001:db8::1", "224.0.0.1"} {
		require.False(t, publicIP(netip.MustParseAddr(ip)), ip)
	}
	require.True(t, publicIP(netip.MustParseAddr("8.8.8.8")))
	require.True(t, publicIP(netip.MustParseAddr("2606:4700:4700::1111")))
	c := testConfig()
	c.AllowInternalURLs = false
	for _, raw := range []string{"file:///etc/passwd", "ftp://example.com/a", "http://user:password@example.com/a", "http://127.0.0.1/a", "http://[::1]/a", "https://example.com:8443/a", "https://example.com/a#fragment"} {
		_, e := c.validateURL(raw)
		require.Error(t, e, raw)
	}
	c.AllowedHosts = []string{"*.example.com"}
	c.DeniedHosts = []string{"blocked.example.com"}
	_, e := c.validateURL("https://cdn.example.com/a")
	require.NoError(t, e)
	_, e = c.validateURL("https://blocked.example.com/a")
	require.Error(t, e)
	_, e = c.validateURL("https://example.com/a")
	require.Error(t, e)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("private server must never be contacted") }))
	defer server.Close()
	_, e = c.httpClient().Get(server.URL)
	require.Error(t, e)
	client := c.httpClient()
	req, _ := http.NewRequest("GET", "http://127.0.0.1/private", nil)
	require.Error(t, client.CheckRedirect(req, []*http.Request{req}))
}
func TestPolicyInheritanceAndCeilings(t *testing.T) {
	c := testConfig()
	c.SpeedLimitPerUser = 100
	p := Policy{Access: "disabled", MaxActive: 5}.Inherit(Policy{Access: "enabled", MaxFileSize: 500, SpeedLimit: 50})
	require.Equal(t, "disabled", p.Access)
	require.Equal(t, int64(500), p.MaxFileSize)
	effective := c.Effective(p)
	require.Equal(t, 2, effective.MaxActive)
	require.Equal(t, int64(50), effective.SpeedLimit)
	require.Equal(t, "enabled", Policy{}.Inherit(Policy{Access: "enabled"}).Access)
	require.Error(t, (Policy{Access: "yes"}).Validate())
	require.Error(t, (Policy{SpeedLimit: -1}).Validate())
	require.Equal(t, int64(100), c.Effective(Policy{SpeedLimit: 200}).SpeedLimit)
	require.Equal(t, int64(10), c.Effective(Policy{MaxStagingSize: 10}).MaxFileSize)
}
func TestCompletionEncryptionAndOwnership(t *testing.T) {
	m := testManager(t, testHooks())
	m.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return response(r, 200, "hello", 5), nil })
	j := enqueue(t, m, "alice")
	require.NotContains(t, j.Source, "secret")
	r, e := m.Get(j.ID, nil)
	require.NoError(t, e)
	require.True(t, r.SourceURL.IsEncrypted())
	other := Owner{Username: "bob", ID: 1, CreatedAt: 2}
	_, e = m.Get(j.ID, &other)
	require.ErrorIs(t, e, ErrNotFound)
	recreated := r.Owner
	recreated.CreatedAt++
	_, e = m.Get(j.ID, &recreated)
	require.ErrorIs(t, e, ErrNotFound)
	require.Empty(t, m.List(&other))
	_, e = m.Action(j.ID, &other, "cancel", "")
	require.ErrorIs(t, e, ErrNotFound)
	m.start(r)
	waitFor(t, func() bool { return state(m, j.ID) == "completed" })
	r, e = m.Get(j.ID, nil)
	require.NoError(t, e)
	require.Nil(t, r.SourceURL)
	require.Equal(t, int64(5), r.Job.BytesImported)
	require.Equal(t, "import", r.Job.Phase)
	_, e = os.Stat(m.stagePath(j.ID))
	require.True(t, os.IsNotExist(e))
	require.NoError(t, m.Close())
	data, e := os.ReadFile(m.config.DatabasePath)
	require.NoError(t, e)
	require.False(t, bytes.Contains(data, []byte("signature=secret")))
}
func TestPersistentRecoveryAndCleanup(t *testing.T) {
	k := kms.Configuration{}
	require.NoError(t, k.Initialize())
	base := t.TempDir()
	c := testConfig()
	m, e := Open(c, base, testHooks())
	require.NoError(t, e)
	j := enqueue(t, m, "alice")
	r, e := m.Get(j.ID, nil)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(m.stagePath(j.ID), []byte("abc"), 0600))
	m.mu.Lock()
	m.jobs[j.ID].ETag = `"version1"`
	m.jobs[j.ID].Job.State = "fetching"
	require.NoError(t, m.saveLocked(m.jobs[j.ID]))
	m.mu.Unlock()
	require.NoError(t, m.Close())
	m, e = Open(c, base, testHooks())
	require.NoError(t, e)
	defer m.Close()
	r, e = m.Get(j.ID, &r.Owner)
	require.NoError(t, e)
	require.Equal(t, "paused", r.Job.State)
	require.Equal(t, int64(3), r.Job.BytesFetched)
	require.Equal(t, `"version1"`, r.ETag)
	secret := r.SourceURL.Clone()
	require.NoError(t, secret.Decrypt())
	require.Contains(t, secret.GetPayload(), "signature=secret")
	m.mu.Lock()
	m.jobs[j.ID].Job.UpdatedAt = time.Now().Add(-8 * 24 * time.Hour).UnixMilli()
	m.mu.Unlock()
	m.cleanup()
	r, e = m.Get(j.ID, nil)
	require.NoError(t, e)
	require.Equal(t, "canceled", r.Job.State)
	require.Nil(t, r.SourceURL)
	_, e = os.Stat(m.stagePath(j.ID))
	require.True(t, os.IsNotExist(e))
	_, e = m.Action(j.ID, &r.Owner, "delete", "")
	require.NoError(t, e)
	_, e = m.Get(j.ID, nil)
	require.ErrorIs(t, e, ErrNotFound)
	// A second process cannot own the same queue.
	_, e = Open(c, base, testHooks())
	require.Error(t, e)
}

type interruptBody struct {
	ctx   context.Context
	first bool
}

func (b *interruptBody) Read(p []byte) (int, error) {
	if !b.first {
		b.first = true
		return copy(p, "abc"), nil
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *interruptBody) Close() error { return nil }
func TestPauseResumeWithValidator(t *testing.T) {
	m := testManager(t, testHooks())
	m.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp := response(r, 200, "", 6)
		resp.Body = &interruptBody{ctx: r.Context()}
		return resp, nil
	})
	j := enqueue(t, m, "alice")
	r, _ := m.Get(j.ID, nil)
	m.start(r)
	waitFor(t, func() bool { r, _ := m.Get(j.ID, nil); return r.Job.BytesFetched == 3 })
	_, e := m.Action(j.ID, &r.Owner, "pause", "")
	require.NoError(t, e)
	waitFor(t, func() bool { return noWorker(m, j.ID) })
	require.Equal(t, "paused", state(m, j.ID))
	m.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "bytes=3-", req.Header.Get("Range"))
		require.Equal(t, `"version1"`, req.Header.Get("If-Range"))
		resp := response(req, 206, "def", 3)
		resp.Header.Set("Content-Range", "bytes 3-5/6")
		return resp, nil
	})
	_, e = m.Action(j.ID, &r.Owner, "resume", "")
	require.NoError(t, e)
	r, _ = m.Get(j.ID, nil)
	m.start(r)
	waitFor(t, func() bool { return state(m, j.ID) == "completed" })
	r, _ = m.Get(j.ID, nil)
	require.Equal(t, int64(6), r.Job.BytesImported)
}
func TestChangedSourceRestartsAndInvalidRangesFail(t *testing.T) {
	for _, status := range []int{200, 206} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			m := testManager(t, testHooks())
			j := enqueue(t, m, "alice")
			require.NoError(t, os.WriteFile(m.stagePath(j.ID), []byte("old"), 0600))
			m.mu.Lock()
			m.jobs[j.ID].Representation = fmt.Sprintf("%x", sha256.Sum256([]byte("https://example.com/file?signature=secret")))
			m.jobs[j.ID].ETag = `"old"`
			m.jobs[j.ID].Job.BytesFetched = 3
			m.mu.Unlock()
			m.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				resp := response(req, status, "new", 3)
				resp.Header.Set("Etag", `"new"`)
				resp.Header.Set("Content-Range", "bytes 0-2/3")
				return resp, nil
			})
			r, _ := m.Get(j.ID, nil)
			m.start(r)
			if status == 200 {
				waitFor(t, func() bool { return state(m, j.ID) == "completed" })
				r, _ = m.Get(j.ID, nil)
				require.Contains(t, r.Job.Notice, "restarted")
				require.Equal(t, int64(3), r.Job.BytesImported)
			} else {
				waitFor(t, func() bool { return state(m, j.ID) == "failed" })
				r, _ = m.Get(j.ID, nil)
				require.Contains(t, r.Job.Error, "invalid resume")
			}
		})
	}
}
func TestLimitsRevocationAndImportRetry(t *testing.T) {
	var allowed atomic.Bool
	allowed.Store(true)
	var imported atomic.Int32
	hooks := testHooks()
	hooks.Check = func(Record) (Policy, error) {
		if !allowed.Load() {
			return Policy{}, ErrDisabled
		}
		return Policy{Access: "enabled"}, nil
	}
	hooks.Import = func(ctx context.Context, r Record, p string, progress func(int64)) error {
		if imported.Add(1) == 1 {
			return errors.New("storage failure")
		}
		return nil
	}
	cfg := testConfig()
	cfg.MaxPendingPerUser = 1
	m := testManagerConfig(t, cfg, hooks)
	m.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) { return response(req, 200, "data", 4), nil })
	j := enqueue(t, m, "alice")
	r, _ := m.Get(j.ID, nil)
	m.start(r)
	waitFor(t, func() bool { return state(m, j.ID) == "failed" })
	waitFor(t, func() bool { return noWorker(m, j.ID) })
	r, _ = m.Get(j.ID, nil)
	require.True(t, r.FetchComplete)
	_, e := m.Action(j.ID, &r.Owner, "retry", "/newname")
	require.NoError(t, e)
	r, _ = m.Get(j.ID, nil)
	m.start(r)
	waitFor(t, func() bool { return state(m, j.ID) == "completed" })
	r, _ = m.Get(j.ID, nil)
	require.Equal(t, "/newname", r.Job.Destination)
	require.Equal(t, 0, r.Job.Attempts)
	// Admission and revoked grants.
	allowed.Store(false)
	_, e = m.Create(r.Owner, "", "https://example.com/a", "/a")
	require.ErrorIs(t, e, ErrDisabled)
	allowed.Store(true)

	j = enqueue(t, m, "alice")
	_, e = m.Create(r.Owner, "", "https://example.com/a", "/b")
	require.ErrorIs(t, e, ErrLimit)
	m.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp := response(req, 200, "", 6)
		resp.Body = &interruptBody{ctx: req.Context()}
		return resp, nil
	})
	r, _ = m.Get(j.ID, nil)
	m.start(r)
	waitFor(t, func() bool { r, _ := m.Get(j.ID, nil); return r.Job.BytesFetched == 3 })
	allowed.Store(false)
	m.monitor()
	waitFor(t, func() bool { return noWorker(m, j.ID) })
	require.Equal(t, "failed", state(m, j.ID))
}
func TestFileLimitAndTruncatedBody(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(strconv.FormatBool(unknown), func(t *testing.T) {
			cfg := testConfig()
			cfg.MaxFileSize = 3
			m := testManagerConfig(t, cfg, testHooks())
			m.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				size := int64(4)
				if unknown {
					size = -1
				}
				return response(req, 200, "four", size), nil
			})
			j := enqueue(t, m, "alice")
			r, _ := m.Get(j.ID, nil)
			m.start(r)
			waitFor(t, func() bool { return state(m, j.ID) == "failed" })
			r, _ = m.Get(j.ID, nil)
			require.Contains(t, r.Job.Error, "size limit")
		})
	}
	m := testManager(t, testHooks())
	m.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) { return response(req, 200, "abc", 6), nil })
	j := enqueue(t, m, "alice")
	r, _ := m.Get(j.ID, nil)
	m.start(r)
	waitFor(t, func() bool { return state(m, j.ID) == "failed" })
	r, _ = m.Get(j.ID, nil)
	require.Contains(t, r.Job.Error, "expected size")
}
func TestAggregateConcurrencyAndReservation(t *testing.T) {
	hooks := testHooks()
	hooks.Import = func(ctx context.Context, r Record, p string, progress func(int64)) error {
		<-ctx.Done()
		return ctx.Err()
	}
	cfg := testConfig()
	cfg.MaxActive = 2
	cfg.MaxActivePerUser = 1
	m := testManagerConfig(t, cfg, hooks)
	m.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) { return response(req, 200, "x", 1), nil })
	a := enqueue(t, m, "alice")
	a2 := enqueue(t, m, "alice")
	b := enqueue(t, m, "bob")
	c := enqueue(t, m, "charlie")
	m.schedule()
	waitFor(t, func() bool { return state(m, a.ID) == "importing" })
	m.schedule()
	require.Equal(t, "queued", state(m, a2.ID))
	require.Equal(t, "queued", state(m, c.ID))
	waitFor(t, func() bool { return state(m, b.ID) == "importing" })
	r, _ := m.Get(a.ID, nil)
	_, e := m.Action(a.ID, &r.Owner, "cancel", "")
	require.NoError(t, e)
	waitFor(t, func() bool { return noWorker(m, a.ID) })
	m.schedule()
	waitFor(t, func() bool { return state(m, c.ID) == "importing" })
}
func TestLimiterUsesSharedUserBucket(t *testing.T) {
	cfg := testConfig()
	cfg.SpeedLimitPerUser = 65536
	cfg.MaxActive = 2
	m := testManagerConfig(t, cfg, testHooks())
	m.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(req, 200, strings.Repeat("x", 65536), 65536), nil
	})
	a := enqueue(t, m, "alice")
	b := enqueue(t, m, "alice")
	r, _ := m.Get(a.ID, nil)
	m.start(r)
	r, _ = m.Get(b.ID, nil)
	start := time.Now()
	m.start(r)
	waitFor(t, func() bool { return state(m, a.ID) == "completed" && state(m, b.ID) == "completed" })
	require.GreaterOrEqual(t, time.Since(start), 800*time.Millisecond)
}
func TestConfigPathsAndInvalidSettings(t *testing.T) {
	c := testConfig()
	require.NoError(t, c.Validate())
	c.resolvePaths("/data")
	require.Equal(t, filepath.Join("/data", "url-downloads", "jobs.db"), c.DatabasePath)
	c.MaxActive = 0
	require.Error(t, c.Validate())
	c = testConfig()
	c.AllowedPorts = []int{65536}
	require.Error(t, c.Validate())
}
