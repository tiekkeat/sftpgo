// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !nos3

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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/require"
)

func TestS3ExclusivePublication(t *testing.T) {
	for _, multipart := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "multipart"}[multipart], func(t *testing.T) {
			var mu sync.Mutex
			exists := false
			conditions := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				q := r.URL.Query()
				w.Header().Set("Content-Type", "application/xml")
				if r.Method == "POST" && q.Has("uploads") {
					io.WriteString(w, `<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>target</Key><UploadId>upload</UploadId></InitiateMultipartUploadResult>`)
					return
				}
				if r.Method == "PUT" && q.Has("partNumber") {
					w.Header().Set("ETag", `"part"`)
					return
				}
				if r.Method == "DELETE" {
					w.WriteHeader(204)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				conditions = append(conditions, r.Header.Get("If-None-Match"))
				if exists {
					w.WriteHeader(412)
					io.WriteString(w, `<Error><Code>PreconditionFailed</Code><Message>Exists</Message></Error>`)
					return
				}
				exists = true
				if r.Method == "POST" {
					io.WriteString(w, `<CompleteMultipartUploadResult><Bucket>bucket</Bucket><Key>target</Key><ETag>"complete"</ETag></CompleteMultipartUploadResult>`)
				} else {
					w.Header().Set("ETag", `"complete"`)
				}
			}))
			defer server.Close()
			client := s3.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")}, func(o *s3.Options) { o.BaseEndpoint = aws.String(server.URL); o.UsePathStyle = true })
			fs := &S3Fs{connectionID: "exclusive-test", localTempDir: t.TempDir(), config: &S3FsConfig{BaseS3FsConfig: sdk.BaseS3FsConfig{Bucket: "bucket", UploadPartSize: 5 << 20, UploadConcurrency: 2, UploadPartMaxTime: 5}}, svc: client, ctxTimeout: 5 * time.Second}
			data := "x"
			if multipart {
				data = strings.Repeat("x", 6<<20)
			}
			for attempt := 0; attempt < 2; attempt++ {
				_, writer, cancel, e := fs.Create("target", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0)
				require.NoError(t, e)
				require.NotNil(t, cancel)
				_, we := io.Copy(writer, strings.NewReader(data))
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
			require.True(t, fs.SupportsExclusiveCreate())
			fs.config.Endpoint = server.URL
			require.False(t, fs.SupportsExclusiveCreate())
		})
	}
}
