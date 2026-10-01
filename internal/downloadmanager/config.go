// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package downloadmanager manages persistent, server-side HTTP downloads.
package downloadmanager

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
)

// Config controls admission, staging, and outbound HTTP requests. Speeds are bytes/s.
type Config struct {
	Enabled               bool     `json:"enabled" mapstructure:"enabled"`
	DatabasePath          string   `json:"database_path" mapstructure:"database_path"`
	StagingPath           string   `json:"staging_path" mapstructure:"staging_path"`
	MaxActive             int      `json:"max_active" mapstructure:"max_active"`
	MaxActivePerUser      int      `json:"max_active_per_user" mapstructure:"max_active_per_user"`
	MaxPending            int      `json:"max_pending" mapstructure:"max_pending"`
	MaxPendingPerUser     int      `json:"max_pending_per_user" mapstructure:"max_pending_per_user"`
	MaxFileSize           int64    `json:"max_file_size" mapstructure:"max_file_size"`
	MaxStagingSize        int64    `json:"max_staging_size" mapstructure:"max_staging_size"`
	MaxStagingPerUser     int64    `json:"max_staging_per_user" mapstructure:"max_staging_per_user"`
	MinFreeSpace          int64    `json:"min_free_space" mapstructure:"min_free_space"`
	SpeedLimit            int64    `json:"speed_limit" mapstructure:"speed_limit"`
	SpeedLimitPerUser     int64    `json:"speed_limit_per_user" mapstructure:"speed_limit_per_user"`
	RetryMax              int      `json:"retry_max" mapstructure:"retry_max"`
	ConnectTimeout        int      `json:"connect_timeout" mapstructure:"connect_timeout"`
	HeaderTimeout         int      `json:"header_timeout" mapstructure:"header_timeout"`
	IdleTimeout           int      `json:"idle_timeout" mapstructure:"idle_timeout"`
	MaxRedirects          int      `json:"max_redirects" mapstructure:"max_redirects"`
	StagingRetentionHours int      `json:"staging_retention_hours" mapstructure:"staging_retention_hours"`
	HistoryRetentionHours int      `json:"history_retention_hours" mapstructure:"history_retention_hours"`
	AllowedPorts          []int    `json:"allowed_ports" mapstructure:"allowed_ports"`
	AllowedHosts          []string `json:"allowed_hosts" mapstructure:"allowed_hosts"`
	DeniedHosts           []string `json:"denied_hosts" mapstructure:"denied_hosts"`
}

// DefaultConfig leaves the feature disabled and bounds queue and staging resources.
func DefaultConfig() Config {
	return Config{
		DatabasePath:          "url-downloads/jobs.db",
		StagingPath:           "url-downloads/staging",
		MaxActive:             8,
		MaxActivePerUser:      2,
		MaxPending:            1000,
		MaxPendingPerUser:     100,
		MaxFileSize:           100 << 30,
		MaxStagingSize:        500 << 30,
		MaxStagingPerUser:     200 << 30,
		MinFreeSpace:          5 << 30,
		RetryMax:              3,
		ConnectTimeout:        15,
		HeaderTimeout:         30,
		IdleTimeout:           120,
		MaxRedirects:          5,
		StagingRetentionHours: 168,
		HistoryRetentionHours: 720,
		AllowedPorts:          []int{80, 443},
		AllowedHosts:          []string{},
		DeniedHosts:           []string{},
	}
}

func (c *Config) Validate() error {
	if c.DatabasePath == "" || c.StagingPath == "" {
		return errors.New("download database and staging paths are required")
	}
	if c.MaxActive < 1 || c.MaxActivePerUser < 1 || c.MaxPending < 1 || c.MaxPendingPerUser < 1 || c.MaxFileSize < 1 || c.MaxStagingSize < c.MaxFileSize || c.MaxStagingPerUser < c.MaxFileSize {
		return errors.New("invalid download admission or staging limits")
	}
	if c.MinFreeSpace < 0 || c.SpeedLimit < 0 || c.SpeedLimitPerUser < 0 || c.RetryMax < 0 || c.RetryMax > 10 || c.ConnectTimeout < 1 || c.HeaderTimeout < 1 || c.IdleTimeout < 1 || c.MaxRedirects < 0 || c.StagingRetentionHours < 1 || c.HistoryRetentionHours < 1 {
		return errors.New("invalid download speed, retry, timeout or retention setting")
	}
	if len(c.AllowedPorts) == 0 {
		return errors.New("at least one download port must be allowed")
	}
	for _, p := range c.AllowedPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid download port %d", p)
		}
	}
	return nil
}

func (c *Config) resolvePaths(base string) {
	if !filepath.IsAbs(c.DatabasePath) {
		c.DatabasePath = filepath.Join(base, c.DatabasePath)
	}
	if !filepath.IsAbs(c.StagingPath) {
		c.StagingPath = filepath.Join(base, c.StagingPath)
	}
}

// Policy is stored on users and primary groups. Zero limits inherit; access is tri-state.
type Policy struct {
	Access         string `json:"access,omitempty"`
	MaxActive      int    `json:"max_active,omitempty"`
	MaxPending     int    `json:"max_pending,omitempty"`
	SpeedLimit     int64  `json:"speed_limit,omitempty"`
	MaxFileSize    int64  `json:"max_file_size,omitempty"`
	MaxStagingSize int64  `json:"max_staging_size,omitempty"`
}

func (p Policy) Validate() error {
	if !slices.Contains([]string{"", "inherit", "enabled", "disabled"}, p.Access) || p.MaxActive < 0 || p.MaxPending < 0 || p.SpeedLimit < 0 || p.MaxFileSize < 0 || p.MaxStagingSize < 0 {
		return errors.New("invalid URL download policy")
	}
	return nil
}

// Inherit fills unset properties from a primary group, without overriding an explicit denial.
func (p Policy) Inherit(g Policy) Policy {
	if p.Access == "" || p.Access == "inherit" {
		p.Access = g.Access
	}
	if p.MaxActive == 0 {
		p.MaxActive = g.MaxActive
	}
	if p.MaxPending == 0 {
		p.MaxPending = g.MaxPending
	}
	if p.SpeedLimit == 0 {
		p.SpeedLimit = g.SpeedLimit
	}
	if p.MaxFileSize == 0 {
		p.MaxFileSize = g.MaxFileSize
	}
	if p.MaxStagingSize == 0 {
		p.MaxStagingSize = g.MaxStagingSize
	}
	return p
}
func positiveMin(a, b int64) int64 {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	return min(a, b)
}
func (c Config) Effective(p Policy) Policy {
	p.MaxActive = int(positiveMin(int64(p.MaxActive), int64(c.MaxActivePerUser)))
	p.MaxPending = int(positiveMin(int64(p.MaxPending), int64(c.MaxPendingPerUser)))
	p.SpeedLimit = positiveMin(p.SpeedLimit, c.SpeedLimitPerUser)
	p.MaxFileSize = positiveMin(p.MaxFileSize, c.MaxFileSize)
	p.MaxStagingSize = positiveMin(p.MaxStagingSize, c.MaxStagingPerUser)
	p.MaxFileSize = min(p.MaxFileSize, p.MaxStagingSize)
	return p
}
