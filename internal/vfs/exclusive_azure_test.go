// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noazblob

package vfs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/require"
)

func TestAzureExclusivePublication(t *testing.T) {
	var mu sync.Mutex
	exists := false
	conditions := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Query().Get("comp") == "block" {
			w.WriteHeader(201)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		conditions = append(conditions, r.Header.Get("If-None-Match"))
		if exists {
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("x-ms-error-code", "BlobAlreadyExists")
			w.WriteHeader(412)
			io.WriteString(w, `<Error><Code>BlobAlreadyExists</Code><Message>Exists</Message></Error>`)
			return
		}
		exists = true
		w.Header().Set("ETag", `"complete"`)
		w.WriteHeader(201)
	}))
	defer server.Close()
	client, e := container.NewClientWithNoCredential(server.URL+"/container", nil)
	require.NoError(t, e)
	fs := &AzureBlobFs{connectionID: "exclusive-test", localTempDir: t.TempDir(), config: &AzBlobFsConfig{SASURL: kms.NewEmptySecret(), BaseAzBlobFsConfig: sdk.BaseAzBlobFsConfig{UploadPartSize: 5 << 20, UploadConcurrency: 2}}, containerClient: client, ctxTimeout: 5 * time.Second}
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
	require.Equal(t, []string{"*", "*"}, conditions)
	require.True(t, exists)
	mu.Unlock()
}
