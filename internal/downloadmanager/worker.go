// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only
package downloadmanager

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

type fetchError struct {
	message string
	retry   bool
}

func (e *fetchError) Error() string                 { return e.message }
func fetchFailure(message string, retry bool) error { return &fetchError{message, retry} }

var rangePattern = regexp.MustCompile(`^bytes ([0-9]+)-([0-9]+)/([0-9]+)$`)

func parseRange(value string) (start, end, total int64, err error) {
	parts := rangePattern.FindStringSubmatch(value)
	if len(parts) != 4 {
		return 0, 0, 0, errors.New("invalid content range")
	}
	start, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return
	}
	end, err = strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return
	}
	total, err = strconv.ParseInt(parts[3], 10, 64)
	if err == nil && (start > end || end >= total) {
		err = errors.New("invalid content range")
	}
	return
}
func strongETag(s string) bool {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for _, b := range []byte(s[1 : len(s)-1]) {
		if b < 0x21 || b == 0x22 || b == 0x7f {
			return false
		}
	}
	return true
}
func (m *Manager) run(ctx context.Context, id string) {
	defer m.wg.Done()
	var err error
	r, _ := m.Get(id, nil)
	if !r.FetchComplete {
		for retry := 0; retry <= m.config.RetryMax; retry++ {
			if ctx.Err() != nil {
				err = ctx.Err()
				break
			}
			m.mu.Lock()
			m.jobs[id].Job.Attempts++
			err = m.saveLocked(m.jobs[id])
			m.mu.Unlock()
			if err != nil {
				break
			}
			err = m.fetch(ctx, id)
			if err == nil {
				break
			}
			var fe *fetchError
			if !errors.As(err, &fe) || !fe.retry || retry == m.config.RetryMax {
				break
			}
			timer := time.NewTimer(time.Duration(1<<retry) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				err = ctx.Err()
			case <-timer.C:
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	if err == nil && ctx.Err() == nil {
		r, _ = m.Get(id, nil)
		if _, e := m.check(r); e != nil {
			err = errors.New("Download access is no longer available")
		} else {
			m.mu.Lock()
			cur := m.jobs[id]
			if cur.Job.State == "fetching" || cur.Job.State == "importing" {
				cur.Job.Phase = "import"
				cur.Job.State = "importing"
				cur.Job.BytesImported = 0
				cur.Job.UpdatedAt = time.Now().UnixMilli()
				err = m.saveLocked(cur)
			} else {
				err = context.Canceled
			}
			m.mu.Unlock()
			if err == nil {
				r, _ = m.Get(id, nil)
				last := time.Now()
				lastBytes := int64(0)
				err = m.hooks.Import(ctx, r, m.stagePath(id), func(n int64) {
					m.mu.Lock()
					defer m.mu.Unlock()
					cur := m.jobs[id]
					if cur.Job.State != "importing" {
						return
					}
					cur.Job.BytesImported = n
					if time.Since(last) >= time.Second {
						cur.Job.Speed = int64(float64(n-lastBytes) / time.Since(last).Seconds())
						cur.Job.UpdatedAt = time.Now().UnixMilli()
						if cur.Job.Speed > 0 {
							cur.Job.ETASeconds = max(int64(0), cur.Job.TotalBytes-n) / cur.Job.Speed
						}
						if m.saveLocked(cur) != nil {
							m.running[id].cancel()
						}
						last = time.Now()
						lastBytes = n
					}
				})
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.jobs[id]
	delete(m.running, id)
	cur.Job.Speed = 0
	cur.Job.ETASeconds = -1
	cur.Job.UpdatedAt = time.Now().UnixMilli()
	if cur.Job.State == "fetching" || cur.Job.State == "importing" {
		if err == nil && ctx.Err() == nil {
			cur.Job.State = "completed"
			cur.SourceURL = nil
			m.removeStageLocked(cur)
		} else {
			cur.Job.State = "failed"
			cur.Job.Error = "Download interrupted"
			if err != nil {
				var fe *fetchError
				if errors.As(err, &fe) {
					cur.Job.Error = fe.message
				} else if ctx.Err() == nil {
					cur.Job.Error = "Import failed: permissions, quota, destination conflict, or storage error"
				}
			}
			failuresMetric.Inc()
		}
	}
	if cur.Job.State == "canceled" {
		m.removeStageLocked(cur)
	}
	_ = m.saveLocked(cur)
}
func (m *Manager) fetch(ctx context.Context, id string) error {
	r, err := m.Get(id, nil)
	if err != nil {
		return err
	}
	if r.SourceURL == nil {
		return fetchFailure("Source URL is no longer available", false)
	}
	secret := r.SourceURL.Clone()
	if err = secret.Decrypt(); err != nil {
		return fetchFailure("Unable to decrypt source URL", false)
	}
	u, err := m.config.validateURL(secret.GetPayload())
	if err != nil {
		return fetchFailure("Source URL is no longer allowed", false)
	}
	file, err := os.OpenFile(m.stagePath(id), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fetchFailure("Unable to open staging file", false)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fetchFailure("Unable to inspect staging file", false)
	}
	offset := info.Size()
	if offset > 0 && (!strongETag(r.ETag) || r.Representation == "") {
		offset = 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fetchFailure("Invalid source request", false)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "SFTPGo-URLDownload")
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		req.Header.Set("If-Range", r.ETag)
	}
	client := m.httpClient
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fetchFailure("Source request failed or was blocked by network policy", true)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fetchFailure(fmt.Sprintf("Source returned HTTP %d", resp.StatusCode), resp.StatusCode == 429 || resp.StatusCode >= 500)
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return fetchFailure("Source returned an unsupported content encoding", false)
	}
	representation := fmt.Sprintf("%x", sha256.Sum256([]byte(resp.Request.URL.String())))
	total := resp.ContentLength
	if resp.StatusCode == http.StatusPartialContent && representation != r.Representation {
		m.mu.Lock()
		m.jobs[id].ETag = ""
		m.jobs[id].Job.Notice = "Source destination changed; restarting from zero"
		err = m.saveLocked(m.jobs[id])
		m.mu.Unlock()
		if err != nil {
			return err
		}
		return fetchFailure("Source destination changed; restart required", true)
	}
	if resp.StatusCode == http.StatusPartialContent {
		start, end, size, e := parseRange(resp.Header.Get("Content-Range"))
		if e != nil || offset == 0 || start != offset || end != size-1 || resp.Header.Get("ETag") != r.ETag || (resp.ContentLength >= 0 && resp.ContentLength != end-start+1) {
			return fetchFailure("Source returned an invalid resume response", false)
		}
		total = size
	} else {
		if offset > 0 || info.Size() > 0 {
			r.Job.Notice = "Source cannot safely resume; restarted from zero"
		}
		offset = 0
		if err = file.Truncate(0); err != nil {
			return fetchFailure("Unable to reset staging file", false)
		}
	}
	if _, err = file.Seek(offset, io.SeekStart); err != nil {
		return fetchFailure("Unable to seek staging file", false)
	}
	m.mu.Lock()
	cur := m.jobs[id]
	p := m.running[id].policy
	if total > p.MaxFileSize || offset > p.MaxFileSize {
		m.mu.Unlock()
		return fetchFailure("File exceeds the configured size limit", false)
	}
	if total >= 0 {
		m.running[id].reserve = max(offset, total)
	}
	cur.Job.TotalBytes = total
	cur.StagedBytes = offset
	cur.Representation = representation
	cur.Job.BytesFetched = offset
	cur.Job.Notice = r.Job.Notice
	cur.ETag = ""
	if strongETag(resp.Header.Get("ETag")) {
		cur.ETag = resp.Header.Get("ETag")
	}
	err = m.saveLocked(cur)
	userRate := m.userRates[r.Owner.Username]
	m.mu.Unlock()
	if err != nil {
		return err
	}
	buf := make([]byte, 64*1024)
	written := offset
	last := time.Now()
	lastBytes := offset
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		m.mu.Lock()
		p = m.running[id].policy
		m.mu.Unlock()
		size := int(min(int64(len(buf)), max(int64(1), p.MaxFileSize-written+1)))
		n, readErr := resp.Body.Read(buf[:size])
		if n > 0 {
			bytesMetric.Add(float64(n))
			if err = m.globalRate.WaitN(ctx, n); err != nil {
				return err
			}
			if err = userRate.WaitN(ctx, n); err != nil {
				return err
			}
			if written+int64(n) > p.MaxFileSize {
				return fetchFailure("File exceeds the configured size limit", false)
			}
			usage, e := stagingFree(m.config.StagingPath)
			if e != nil || usage < int64(n)+m.config.MinFreeSpace {
				return fetchFailure("Insufficient free staging disk space", false)
			}
			count, e := file.Write(buf[:n])
			written += int64(count)
			m.mu.Lock()
			m.jobs[id].StagedBytes = written
			m.jobs[id].Job.BytesFetched = written
			m.mu.Unlock()
			if e != nil || count != n {
				return fetchFailure("Unable to write staging file", false)
			}
			m.mu.Lock()
			cur = m.jobs[id]
			cur.Job.BytesFetched = written
			if time.Since(last) >= time.Second {
				cur.Job.Speed = int64(float64(written-lastBytes) / time.Since(last).Seconds())
				cur.Job.UpdatedAt = time.Now().UnixMilli()
				if total >= 0 && cur.Job.Speed > 0 {
					cur.Job.ETASeconds = max(int64(0), total-written) / cur.Job.Speed
				}
				err = m.saveLocked(cur)
				last = time.Now()
				lastBytes = written
			}
			m.mu.Unlock()
			if err != nil {
				return err
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fetchFailure("Source transfer interrupted", true)
			}
			break
		}
	}
	if total >= 0 && written != total {
		return fetchFailure("Source transfer ended before the expected size", true)
	}
	if err = file.Sync(); err != nil {
		return fetchFailure("Unable to persist staged data", false)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur = m.jobs[id]
	if ctx.Err() != nil {
		return ctx.Err()
	}
	cur.Job.TotalBytes = written
	cur.Job.BytesFetched = written
	cur.FetchComplete = true
	return m.saveLocked(cur)
}
