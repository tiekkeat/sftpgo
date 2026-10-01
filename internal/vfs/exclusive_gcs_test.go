// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !nogcs

package vfs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
)

func TestGCSExclusivePublication(t *testing.T) {
	var mu sync.Mutex
	exists := false
	conditions := []string{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			conditions = append(conditions, r.URL.Query().Get("ifGenerationMatch"))
			if exists {
				w.WriteHeader(412)
				io.WriteString(w, `{"error":{"code":412,"message":"Exists"}}`)
				return
			}
			if r.URL.Query().Get("uploadType") == "resumable" {
				w.Header().Set("Location", server.URL+"/upload-session")
				fmt.Fprint(w, `{}`)
			} else {
				exists = true
				fmt.Fprint(w, `{"bucket":"bucket","name":"target","generation":"1","size":"8"}`)
			}
			return
		}
		if r.Method == "PUT" {
			exists = true
			fmt.Fprint(w, `{"bucket":"bucket","name":"target","generation":"1","size":"8"}`)
			return
		}
		t.Errorf("unexpected GCS request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
	}))
	defer server.Close()
	client, e := storage.NewClient(context.Background(), option.WithEndpoint(server.URL), option.WithoutAuthentication(), storage.WithJSONReads())
	require.NoError(t, e)
	defer client.Close()
	fs := &GCSFs{connectionID: "exclusive-test", localTempDir: t.TempDir(), config: &GCSFsConfig{BaseGCSFsConfig: sdk.BaseGCSFsConfig{Bucket: "bucket", UploadPartSize: 5}}, svc: client, ctxTimeout: 5 * time.Second}
	for attempt := 0; attempt < 2; attempt++ {
		_, writer, cancel, e := fs.Create("target", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0)
		require.NoError(t, e)
		require.NotNil(t, cancel)
		_, we := io.Copy(writer, strings.NewReader("contents"))
		ce := writer.Close()
		cancel()
		if attempt == 0 {
			require.NoError(t, we)
			require.NoError(t, ce)
		} else {
			require.Error(t, ce)
		}
	}
	mu.Lock()
	require.Equal(t, []string{"0", "0"}, conditions)
	require.True(t, exists)
	mu.Unlock()
}
