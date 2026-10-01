// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only
package downloadmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/xid"
	"github.com/shirou/gopsutil/v3/disk"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/time/rate"

	"github.com/drakkan/sftpgo/v2/internal/kms"
)

var (
	ErrInvalid     = errors.New("invalid URL download request")
	ErrNotFound    = errors.New("download job not found")
	ErrConflict    = errors.New("download state conflict")
	ErrLimit       = errors.New("download admission limit reached")
	ErrDisabled    = errors.New("URL downloads are disabled")
	queueMetric    = promauto.NewGauge(prometheus.GaugeOpts{Name: "sftpgo_url_downloads_queued", Help: "Queued URL downloads"})
	activeMetric   = promauto.NewGauge(prometheus.GaugeOpts{Name: "sftpgo_url_downloads_active", Help: "Active URL download jobs"})
	stagingMetric  = promauto.NewGauge(prometheus.GaugeOpts{Name: "sftpgo_url_downloads_staging_bytes", Help: "Staged URL download bytes"})
	bytesMetric    = promauto.NewCounter(prometheus.CounterOpts{Name: "sftpgo_url_downloads_fetched_bytes_total", Help: "Bytes fetched from URL sources, including retries"})
	failuresMetric = promauto.NewCounter(prometheus.CounterOpts{Name: "sftpgo_url_downloads_failures_total", Help: "Failed URL download jobs"})
)

// Owner prevents a recreated account from inheriting a prior account's jobs.
type Owner struct {
	Username  string `json:"username"`
	ID        int64  `json:"id"`
	CreatedAt int64  `json:"created_at"`
}

// Job is the public, credential-free job representation.
type Job struct {
	Phase         string `json:"phase"`
	ID            string `json:"id"`
	Username      string `json:"username"`
	Source        string `json:"source"`
	Destination   string `json:"destination"`
	State         string `json:"state"`
	BytesFetched  int64  `json:"bytes_fetched"`
	BytesImported int64  `json:"bytes_imported"`
	TotalBytes    int64  `json:"total_bytes"` // -1 means unknown
	Speed         int64  `json:"speed"`
	ETASeconds    int64  `json:"eta_seconds"` // -1 means unknown
	Attempts      int    `json:"attempts"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
	Error         string `json:"error,omitempty"`
	Notice        string `json:"notice,omitempty"`
}

// Record is persisted; SourceURL is never returned by the API.
type Record struct {
	StagedBytes    int64       `json:"staged_bytes"`
	Representation string      `json:"representation,omitempty"`
	Job            Job         `json:"job"`
	Owner          Owner       `json:"owner"`
	OIDC           bool        `json:"oidc"`
	RemoteAddr     string      `json:"remote_addr"`
	SourceURL      *kms.Secret `json:"source_url,omitempty"`
	ETag           string      `json:"etag,omitempty"`
	FetchComplete  bool        `json:"fetch_complete"`
}

// Hooks connects the manager to authentication and the normal upload pipeline.
type Hooks struct {
	Check  func(Record) (Policy, error)
	Import func(context.Context, Record, string, func(int64)) error
}
type runningJob struct {
	cancel  context.CancelFunc
	reserve int64
	policy  Policy
}

type Manager struct {
	httpClient *http.Client
	mu         sync.Mutex
	config     Config
	hooks      Hooks
	db         *bolt.DB
	jobs       map[string]*Record
	running    map[string]*runningJob
	userRates  map[string]*rate.Limiter
	globalRate *rate.Limiter
	served     map[string]uint64
	sequence   uint64
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	closed     bool
	storageErr error
}

func limiter(speed int64) *rate.Limiter {
	if speed <= 0 {
		return rate.NewLimiter(rate.Inf, 64*1024)
	}
	return rate.NewLimiter(rate.Limit(speed), 64*1024)
}
func Open(c Config, base string, h Hooks) (*Manager, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if h.Check == nil || h.Import == nil {
		return nil, errors.New("download hooks are required")
	}
	c.resolvePaths(base)
	for _, p := range []string{filepath.Dir(c.DatabasePath), c.StagingPath} {
		if err := os.MkdirAll(p, 0700); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(c.StagingPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("staging must be a private directory")
	}
	if err = os.Chmod(c.StagingPath, 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(c.DatabasePath, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open download database: %w", err)
	}
	m := &Manager{config: c, hooks: h, db: db, jobs: map[string]*Record{}, running: map[string]*runningJob{}, userRates: map[string]*rate.Limiter{}, globalRate: limiter(c.SpeedLimit)}
	m.served = map[string]uint64{}
	m.httpClient = c.httpClient()
	m.ctx, m.cancel = context.WithCancel(context.Background())
	err = db.Update(func(tx *bolt.Tx) error {
		meta, e := tx.CreateBucketIfNotExists([]byte("meta"))
		if e != nil {
			return e
		}
		v := meta.Get([]byte("version"))
		if v != nil && string(v) != "1" {
			return errors.New("unsupported download database version")
		}
		if e = meta.Put([]byte("version"), []byte("1")); e != nil {
			return e
		}
		b, e := tx.CreateBucketIfNotExists([]byte("jobs"))
		if e != nil {
			return e
		}
		return b.ForEach(func(k, v []byte) error {
			var r Record
			if e := json.Unmarshal(v, &r); e != nil {
				return e
			}
			if r.Job.ID != string(k) || !validID(r.Job.ID) {
				return errors.New("invalid persisted download job")
			}
			m.jobs[r.Job.ID] = &r
			return nil
		})
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, r := range m.jobs {
		if r.Job.State == "fetching" {
			r.Job.State = "paused"
			r.Job.Notice = "Server restarted; resume to continue"
		}
		if r.Job.State == "importing" {
			r.Job.State = "failed"
			r.Job.Error = "Import interrupted; inspect the destination before retrying"
		}
		if info, e := os.Stat(m.stagePath(r.Job.ID)); e == nil {
			r.StagedBytes = info.Size()
			if r.Job.State != "completed" {
				r.Job.BytesFetched = info.Size()
			}
		} else {
			r.StagedBytes = 0
			if !terminal(r.Job.State) || r.Job.State == "failed" {
				r.Job.BytesFetched = 0
				r.FetchComplete = false
				r.ETag = ""
			}
		}
		if err = m.saveLocked(r); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Only this exclusively locked manager owns the staging directory.
	entries, err := os.ReadDir(c.StagingPath)
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, e := range entries {
		id := e.Name()
		if validID(id) && m.jobs[id] == nil && !e.IsDir() {
			if err = os.Remove(m.stagePath(id)); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	m.wg.Add(1)
	go m.loop()
	return m, nil
}
func validID(id string) bool                  { _, err := xid.FromString(id); return err == nil }
func (m *Manager) stagePath(id string) string { return filepath.Join(m.config.StagingPath, id) }
func terminal(s string) bool                  { return s == "completed" || s == "failed" || s == "canceled" }
func (m *Manager) Config() Config             { return m.config }
func (m *Manager) saveLocked(r *Record) error {
	data, e := json.Marshal(r)
	if e == nil {
		e = m.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("jobs")).Put([]byte(r.Job.ID), data) })
	}
	if e != nil {
		m.storageErr = e
	}
	return e
}
func (m *Manager) check(r Record) (Policy, error) {
	if !m.config.Enabled {
		return Policy{}, ErrDisabled
	}
	p, e := m.hooks.Check(r)
	if e != nil {
		return p, e
	}
	if e = p.Validate(); e != nil {
		return p, e
	}
	if p.Access != "enabled" {
		return p, ErrDisabled
	}
	return m.config.Effective(p), nil
}
func (m *Manager) Limits(r Record) (Policy, error) { return m.check(r) }
func (m *Manager) Create(owner Owner, remoteAddr, rawURL, dest string, oidc ...bool) (Job, error) {
	u, e := m.config.validateURL(rawURL)
	if e != nil {
		return Job{}, fmt.Errorf("%w: %s", ErrInvalid, e)
	}
	now := time.Now().UnixMilli()
	r := &Record{Job: Job{ID: xid.New().String(), Username: owner.Username, Phase: "fetch", Source: displayURL(u), Destination: dest, State: "queued", CreatedAt: now, UpdatedAt: now, TotalBytes: -1, ETASeconds: -1}, Owner: owner, RemoteAddr: remoteAddr}
	if len(oidc) > 0 {
		r.OIDC = oidc[0]
	}
	p, e := m.check(*r)
	if e != nil {
		return Job{}, e
	}
	r.SourceURL = kms.NewPlainSecret(rawURL)
	r.SourceURL.SetAdditionalData("url-download:" + r.Job.ID)
	if e = r.SourceURL.Encrypt(); e != nil {
		return Job{}, errors.New("unable to encrypt source URL")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.storageErr != nil {
		return Job{}, errors.New("download manager unavailable")
	}
	if !m.admitLocked(owner, p) {
		return Job{}, ErrLimit
	}
	if e = m.saveLocked(r); e != nil {
		return Job{}, e
	}
	m.jobs[r.Job.ID] = r
	return r.Job, nil
}
func (m *Manager) admitLocked(owner Owner, p Policy) bool {
	all, user := 0, 0
	for _, r := range m.jobs {
		if !terminal(r.Job.State) {
			all++
			if r.Owner == owner {
				user++
			}
		}
	}
	return all < m.config.MaxPending && user < p.MaxPending
}
func (m *Manager) List(owner *Owner) []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	jobs := []Job{}
	for _, r := range m.jobs {
		if owner == nil || r.Owner == *owner {
			jobs = append(jobs, r.Job)
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt > jobs[j].CreatedAt })
	return jobs
}
func (m *Manager) Get(id string, owner *Owner) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.jobs[id]
	if r == nil || (owner != nil && r.Owner != *owner) {
		return Record{}, ErrNotFound
	}
	res := *r
	if r.SourceURL != nil {
		res.SourceURL = r.SourceURL.Clone()
	}
	return res, nil
}

// Action changes state durably before interrupting a worker. Retry may change destination.
func (m *Manager) Action(id string, owner *Owner, action, dest string) (Job, error) {
	r, e := m.Get(id, owner)
	if e != nil {
		return Job{}, e
	}
	var p Policy
	if action == "resume" || action == "retry" {
		p, e = m.check(r)
		if e != nil {
			return Job{}, e
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.jobs[id]
	if cur == nil {
		return Job{}, ErrNotFound
	}
	if cur.Job.State != r.Job.State {
		return Job{}, ErrConflict
	}
	if m.closed || m.storageErr != nil {
		return Job{}, errors.New("download manager unavailable")
	}
	next := *cur
	active := m.running[id]
	switch action {
	case "pause":
		if next.Job.State != "fetching" && next.Job.State != "queued" {
			return Job{}, ErrConflict
		}
		next.Job.State = "paused"
	case "resume":
		if next.Job.State != "paused" || active != nil {
			return Job{}, ErrConflict
		}
		next.Job.State = "queued"
	case "retry":
		if next.Job.State != "failed" || active != nil {
			return Job{}, ErrConflict
		}
		if !m.admitLocked(next.Owner, p) {
			return Job{}, ErrLimit
		}
		if dest != "" {
			next.Job.Destination = dest
		}
		if !next.FetchComplete && next.SourceURL == nil {
			return Job{}, ErrConflict
		}
		next.Job.State = "queued"
		next.Job.Attempts = 0
		next.Job.BytesImported = 0
	case "cancel":
		if terminal(next.Job.State) {
			return Job{}, ErrConflict
		}
		next.Job.State = "canceled"
		if cur.Job.State == "importing" {
			next.Job.Notice = "Import cancellation requested; inspect the destination"
		}
		next.SourceURL = nil
	case "delete":
		if !terminal(next.Job.State) || active != nil {
			return Job{}, ErrConflict
		}
		if e := os.Remove(m.stagePath(id)); e != nil && !os.IsNotExist(e) {
			return Job{}, e
		}
		if e = m.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("jobs")).Delete([]byte(id)) }); e != nil {
			m.storageErr = e
			return Job{}, e
		}
		delete(m.jobs, id)
		return cur.Job, nil
	default:
		return Job{}, errors.New("unknown download action")
	}
	next.Job.Error = ""
	next.Job.UpdatedAt = time.Now().UnixMilli()
	next.Job.Speed = 0
	next.Job.ETASeconds = -1
	if e = m.saveLocked(&next); e != nil {
		return Job{}, e
	}
	*cur = next
	if active != nil {
		active.cancel()
	} else if action == "cancel" {
		m.removeStageLocked(cur)
	}
	return cur.Job, nil
}
func (m *Manager) removeStageLocked(r *Record) {
	if e := os.Remove(m.stagePath(r.Job.ID)); e == nil || os.IsNotExist(e) {
		r.StagedBytes = 0
		if r.Job.State != "completed" {
			r.Job.BytesFetched = 0
		}
		r.FetchComplete = false
		_ = m.saveLocked(r)
	}
}
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.cancel()
	for id, a := range m.running {
		r := m.jobs[id]
		if r.Job.State == "fetching" {
			r.Job.State = "paused"
			r.Job.Notice = "Server stopped; resume to continue"
		} else if r.Job.State == "importing" {
			r.Job.State = "failed"
			r.Job.Error = "Import interrupted; inspect destination before retrying"
		}
		_ = m.saveLocked(r)
		a.cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
	return m.db.Close()
}
func (m *Manager) loop() {
	defer m.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-tick.C:
			m.monitor()
			m.schedule()
			m.cleanup()
		}
	}
}
func (m *Manager) monitor() {
	m.mu.Lock()
	records := []Record{}
	for id := range m.running {
		records = append(records, *m.jobs[id])
	}
	m.mu.Unlock()
	for _, r := range records {
		p, e := m.check(r)
		m.mu.Lock()
		if a := m.running[r.Job.ID]; a != nil {
			if e != nil || m.jobs[r.Job.ID].Job.BytesFetched > p.MaxFileSize {
				cur := m.jobs[r.Job.ID]
				if cur.Job.State == "fetching" || cur.Job.State == "importing" {
					cur.Job.State = "failed"
					cur.Job.Error = "Access or download limits changed"
					failuresMetric.Inc()
					_ = m.saveLocked(cur)
					a.cancel()
				}
			} else {
				a.policy = p
				if l := m.userRates[r.Owner.Username]; l != nil {
					l.SetLimit(limiter(p.SpeedLimit).Limit())
				}
			}
		}
		m.mu.Unlock()
	}
}
func (m *Manager) schedule() {
	m.mu.Lock()
	candidates := []Record{}
	for _, r := range m.jobs {
		if r.Job.State == "queued" && m.running[r.Job.ID] == nil {
			candidates = append(candidates, *r)
		}
	}
	m.mu.Unlock()
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Job.CreatedAt == candidates[j].Job.CreatedAt {
			return candidates[i].Job.ID < candidates[j].Job.ID
		}
		return candidates[i].Job.CreatedAt < candidates[j].Job.CreatedAt
	})
	// Serve users with the oldest scheduling turn first; new users precede repeats.
	users := []string{}
	seen := map[string]bool{}
	for _, r := range candidates {
		if !seen[r.Owner.Username] {
			users = append(users, r.Owner.Username)
			seen[r.Owner.Username] = true
		}
	}
	m.mu.Lock()
	sort.SliceStable(users, func(i, j int) bool { return m.served[users[i]] < m.served[users[j]] })
	m.mu.Unlock()
	for _, u := range users {
		for _, r := range candidates {
			if r.Owner.Username == u {
				m.start(r)
				break
			}
		}
	}
}
func (m *Manager) start(snapshot Record) {
	p, e := m.check(snapshot)
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.jobs[snapshot.Job.ID]
	if r == nil || r.Job.State != "queued" || m.running[r.Job.ID] != nil || m.closed || m.storageErr != nil {
		return
	}
	if e != nil {
		r.Job.State = "failed"
		r.Job.Error = "Download access is no longer available"
		r.Job.UpdatedAt = time.Now().UnixMilli()
		_ = m.saveLocked(r)
		failuresMetric.Inc()
		return
	}
	if len(m.running) >= m.config.MaxActive {
		return
	}
	count := 0
	used, userUsed := int64(0), int64(0)
	for id, j := range m.jobs {
		size := j.StagedBytes
		if a := m.running[id]; a != nil {
			size = a.reserve
			if j.Owner == r.Owner {
				count++
			}
		}
		used += size
		if j.Owner == r.Owner {
			userUsed += size
		}
	}
	if count >= p.MaxActive {
		return
	}
	reserve := p.MaxFileSize
	if r.Job.TotalBytes >= 0 {
		reserve = min(reserve, max(r.Job.TotalBytes, r.Job.BytesFetched))
	}
	if r.FetchComplete {
		reserve = r.Job.BytesFetched
	}
	if reserve > p.MaxStagingSize || used-r.StagedBytes+reserve > m.config.MaxStagingSize || userUsed-r.StagedBytes+reserve > p.MaxStagingSize {
		return
	}
	usage, e := disk.Usage(m.config.StagingPath)
	if e != nil || usage.Free < uint64(m.config.MinFreeSpace+min(int64(64*1024), max(int64(0), reserve-r.Job.BytesFetched))) {
		return
	}
	if m.userRates[r.Owner.Username] == nil {
		m.userRates[r.Owner.Username] = limiter(p.SpeedLimit)
	} else {
		m.userRates[r.Owner.Username].SetLimit(limiter(p.SpeedLimit).Limit())
	}
	ctx, cancel := context.WithCancel(m.ctx)
	r.Job.Phase = "fetch"
	r.Job.State = "fetching"
	if r.FetchComplete {
		r.Job.Phase = "import"
		r.Job.State = "importing"
	}
	r.Job.UpdatedAt = time.Now().UnixMilli()
	if e = m.saveLocked(r); e != nil {
		cancel()
		return
	}
	m.running[r.Job.ID] = &runningJob{cancel: cancel, reserve: reserve, policy: p}
	m.sequence++
	m.served[r.Owner.Username] = m.sequence
	m.wg.Add(1)
	go m.run(ctx, r.Job.ID)
}
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	queued, staged := 0, int64(0)
	for id, r := range m.jobs {
		if r.Job.State == "queued" {
			queued++
		}
		staged += r.StagedBytes
		if m.running[id] != nil {
			continue
		}
		if (r.Job.State == "completed" || r.Job.State == "canceled") && r.StagedBytes > 0 {
			m.removeStageLocked(r)
		}
		age := now.Sub(time.UnixMilli(r.Job.UpdatedAt))
		if age > time.Duration(m.config.StagingRetentionHours)*time.Hour && r.Job.State != "completed" && r.Job.State != "canceled" {
			m.removeStageLocked(r)
			r.SourceURL = nil
			r.Job.State = "canceled"
			r.Job.Notice = "Expired staging was removed"
			r.Job.UpdatedAt = now.UnixMilli()
			_ = m.saveLocked(r)
		} else if terminal(r.Job.State) && age > time.Duration(m.config.HistoryRetentionHours)*time.Hour {
			if e := os.Remove(m.stagePath(id)); e != nil && !os.IsNotExist(e) {
				continue
			}
			if e := m.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("jobs")).Delete([]byte(id)) }); e != nil {
				m.storageErr = e
				continue
			}
			delete(m.jobs, id)
		}
	}
	queueMetric.Set(float64(queued))
	activeMetric.Set(float64(len(m.running)))
	stagingMetric.Set(float64(staged))
}
