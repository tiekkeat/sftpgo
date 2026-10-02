// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only

package httpd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/downloadmanager"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/kms"
)

func newDownloadTestUser(t *testing.T) dataprovider.User {
	t.Helper()
	u := dataprovider.User{BaseUser: sdk.BaseUser{Username: "url_" + xid.New().String(), Password: "test-password", HomeDir: t.TempDir(), Status: 1, Permissions: map[string][]string{"/": {dataprovider.PermAny}}}, Filters: dataprovider.UserFilters{URLDownloads: downloadmanager.Policy{Access: "enabled"}}}
	require.NoError(t, dataprovider.AddUser(&u, dataprovider.ActionExecutorSystem, "", ""))
	u, e := dataprovider.GetUserWithGroupSettings(u.Username, "")
	require.NoError(t, e)
	t.Cleanup(func() { _ = dataprovider.DeleteUser(u.Username, dataprovider.ActionExecutorSystem, "", "") })
	return u
}
func TestURLDownloadCreateOnlyImport(t *testing.T) {
	u := newDownloadTestUser(t)
	c := downloadConnection(u, "127.0.0.1:1234")
	defer c.CloseFS()
	require.NoError(t, u.CheckFsRoot(c.ID))
	require.NoError(t, common.Connections.Add(c))
	defer common.Connections.Remove(c.ID)
	dest := filepath.Join(u.HomeDir, "existing.txt")
	require.NoError(t, os.WriteFile(dest, []byte("original"), 0600))
	_, e := c.getCreateOnlyWriter("/existing.txt", 3)
	require.ErrorIs(t, e, downloadmanager.ErrConflict)
	data, e := os.ReadFile(dest)
	require.NoError(t, e)
	require.Equal(t, "original", string(data))
	w, e := c.getCreateOnlyWriter("/new.txt", 3)
	require.NoError(t, e)
	_, e = w.Write([]byte("new"))
	require.NoError(t, e)
	require.NoError(t, w.Close())
	data, e = os.ReadFile(filepath.Join(u.HomeDir, "new.txt"))
	require.NoError(t, e)
	require.Equal(t, "new", string(data))
	// A concurrent normal writer winning after preflight must also be preserved.
	require.NoError(t, checkDownloadDestination(c, "/race.txt"))
	fs, p, e := c.GetFsAndResolvedPath("/race.txt")
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(p, []byte("winner"), 0600))
	_, _, _, e = fs.Create(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0)
	require.Error(t, e)
	data, e = os.ReadFile(p)
	require.NoError(t, e)
	require.Equal(t, "winner", string(data))
	require.NoError(t, os.Symlink(dest, filepath.Join(u.HomeDir, "link.txt")))
	_, e = c.getCreateOnlyWriter("/link.txt", 3)
	require.Error(t, e)
	data, e = os.ReadFile(dest)
	require.NoError(t, e)
	require.Equal(t, "original", string(data))
	u.Permissions["/"] = []string{dataprovider.PermDownload}
	denied := downloadConnection(u, "127.0.0.1:1234")
	defer denied.CloseFS()
	_, e = denied.getCreateOnlyWriter("/denied.txt", 1)
	require.Error(t, e)
}
func TestURLDownloadImportQuotaAndEncryptedStorage(t *testing.T) {
	u := newDownloadTestUser(t)
	u.Filters.MaxUploadFileSize = 2
	c := downloadConnection(u, "127.0.0.1:1234")
	defer c.CloseFS()
	require.NoError(t, u.CheckFsRoot(c.ID))
	_, e := c.getCreateOnlyWriter("/large.txt", 3)
	require.ErrorIs(t, e, common.ErrQuotaExceeded)
	u.Filters.MaxUploadFileSize = 0
	u.FsConfig.Provider = sdk.CryptedFilesystemProvider
	u.FsConfig.CryptConfig.Passphrase = kms.NewPlainSecret("a test key")
	stage := filepath.Join(t.TempDir(), "stage")
	require.NoError(t, os.WriteFile(stage, []byte("secret contents"), 0600))
	require.NoError(t, dataprovider.UpdateUser(&u, dataprovider.ActionExecutorSystem, "", ""))
	u, e = dataprovider.GetUserWithGroupSettings(u.Username, "")
	require.NoError(t, e)
	var progress int64
	r := downloadmanager.Record{Owner: downloadOwner(u), RemoteAddr: "127.0.0.1:1234", Job: downloadmanager.Job{Destination: "/secret.txt"}}
	require.NoError(t, importURLDownload(context.Background(), r, stage, func(n int64) { progress = n }))
	require.Equal(t, int64(15), progress)
	data, e := os.ReadFile(filepath.Join(u.HomeDir, "secret.txt"))
	require.NoError(t, e)
	require.NotContains(t, string(data), "secret contents")
	require.Error(t, importURLDownload(context.Background(), r, stage, func(int64) {}))
}
func TestURLDownloadPolicyPersistenceAndPrimaryGroup(t *testing.T) {
	u := newDownloadTestUser(t)
	g := dataprovider.Group{BaseGroup: sdk.BaseGroup{Name: "urlgroup_" + xid.New().String()}, UserSettings: dataprovider.GroupUserSettings{URLDownloads: downloadmanager.Policy{Access: "enabled", MaxActive: 1, SpeedLimit: 1024}}}
	require.NoError(t, dataprovider.AddGroup(&g, dataprovider.ActionExecutorSystem, "", ""))
	defer dataprovider.DeleteGroup(g.Name, dataprovider.ActionExecutorSystem, "", "")
	u.Filters.URLDownloads = downloadmanager.Policy{Access: "inherit"}
	u.Groups = []sdk.GroupMapping{{Name: g.Name, Type: sdk.GroupTypePrimary}}
	require.NoError(t, dataprovider.UpdateUser(&u, dataprovider.ActionExecutorSystem, "", ""))
	effective, e := dataprovider.GetUserWithGroupSettings(u.Username, "")
	require.NoError(t, e)
	require.Equal(t, "enabled", effective.Filters.URLDownloads.Access)
	require.Equal(t, 1, effective.Filters.URLDownloads.MaxActive)
	require.Equal(t, int64(1024), effective.Filters.URLDownloads.SpeedLimit)
	persisted, e := dataprovider.UserExists(u.Username, "")
	require.NoError(t, e)
	persisted.Filters.URLDownloads.Access = "disabled"
	require.NoError(t, dataprovider.UpdateUser(&persisted, dataprovider.ActionExecutorSystem, "", ""))
	effective, e = dataprovider.GetUserWithGroupSettings(u.Username, "")
	require.NoError(t, e)
	require.Equal(t, "disabled", effective.Filters.URLDownloads.Access)
	u, e = dataprovider.UserExists(u.Username, "")
	require.NoError(t, e)
	u.Filters.URLDownloads = downloadmanager.Policy{}
	u.Groups[0].Type = sdk.GroupTypeSecondary
	require.NoError(t, dataprovider.UpdateUser(&u, dataprovider.ActionExecutorSystem, "", ""))
	effective, e = dataprovider.GetUserWithGroupSettings(u.Username, "")
	require.NoError(t, e)
	require.NotEqual(t, "enabled", effective.Filters.URLDownloads.Access)
	g.UserSettings.URLDownloads.SpeedLimit = -1
	require.Error(t, dataprovider.UpdateGroup(&g, nil, dataprovider.ActionExecutorSystem, "", ""))
}
func TestURLDownloadAPIIsolationAndValidation(t *testing.T) {
	alice := newDownloadTestUser(t)
	bob := newDownloadTestUser(t)
	cfg := downloadmanager.DefaultConfig()
	cfg.Enabled = true
	cfg.AllowInternalURLs = false
	cfg.MaxFileSize = 1 << 20
	cfg.MaxStagingSize = 4 << 20
	cfg.MaxStagingPerUser = 2 << 20
	cfg.MinFreeSpace = 0
	old := urlDownloadManager
	require.NoError(t, InitializeURLDownloads(cfg, t.TempDir(), 0))
	defer func() { StopURLDownloads(); urlDownloadManager = old }()
	s := &httpdServer{}
	call := func(method, target, body, user, role string, admin bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		req = req.WithContext(jwt.NewContext(req.Context(), &jwt.Claims{Username: user, Role: role}, nil))
		rctx := chi.NewRouteContext()
		if parts := strings.Split(strings.Trim(target, "/"), "/"); len(parts) > 0 {
			for i, p := range parts {
				if p == "jobs" && i+1 < len(parts) {
					rctx.URLParams.Add("id", parts[i+1])
				}
			}
		}
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		s.handleURLDownloadAPI(rec, req, admin)
		return rec
	}
	rec := call("POST", "/jobs", `{"url":"https://example.com/file?token=secret","destination":"/download.txt"}`, alice.Username, "", false)
	require.Equal(t, 202, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "token=secret")
	var j downloadmanager.Job
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &j))
	require.Equal(t, 200, call("POST", "/jobs/"+j.ID+"/pause", "", alice.Username, "", false).Code)
	require.Equal(t, 404, call("GET", "/jobs/"+j.ID, "", bob.Username, "", false).Code)
	require.Equal(t, 404, call("POST", "/jobs/"+j.ID+"/cancel", "", bob.Username, "", false).Code)
	require.Equal(t, 404, call("GET", "/jobs/"+j.ID, "", "admin", "another-role", true).Code)
	require.Equal(t, 200, call("GET", "/jobs/"+j.ID, "", "admin", "", true).Code)
	require.Equal(t, 400, call("POST", "/jobs", `{"url":"http://127.0.0.1/private","destination":"/a"}`, alice.Username, "", false).Code)
	require.Equal(t, 400, call("POST", "/jobs", `{"url":"https://example.com/file","destination":"/a/../b"}`, alice.Username, "", false).Code)
	require.Equal(t, 400, call("POST", "/jobs", `{"url":"https://example.com/file","destination":"/a","unexpected":true}`, alice.Username, "", false).Code)
	require.Equal(t, 200, call("POST", "/jobs/"+j.ID+"/cancel", "", alice.Username, "", false).Code)
	require.Equal(t, 409, call("POST", "/jobs/"+j.ID+"/resume", "", alice.Username, "", false).Code)
	require.Equal(t, 200, call("DELETE", "/jobs/"+j.ID, "", alice.Username, "", false).Code)
}
func TestURLDownloadTemplatesAndForm(t *testing.T) {
	policy, e := getURLDownloadPolicyFromForm(&http.Request{Form: url.Values{"url_download_access": {"enabled"}, "url_download_max_active": {"2"}, "url_download_speed_limit": {"1024"}}})
	require.NoError(t, e)
	require.Equal(t, int64(1024), policy.SpeedLimit)
	_, e = getURLDownloadPolicyFromForm(&http.Request{Form: url.Values{"url_download_speed_limit": {"-1"}}})
	require.Error(t, e)
	u := newDownloadTestUser(t)
	base := baseClientPage{LoggedUser: &u, commonBasePage: commonBasePage{}, DownloadsURL: "/web/client/downloads"}
	page := clientDownloadsPage{baseClientPage: base, APIURL: "/web/client/downloads/jobs", CanCreate: true, CanManage: true}
	var b bytes.Buffer
	require.NoError(t, clientTemplates["urldownloads.html"].ExecuteTemplate(&b, "base", page))
	require.Contains(t, b.String(), "download-form")
	require.Contains(t, b.String(), "/web/client/downloads/jobs")
	// Every rendered user string stays in textContent or an escaped template context.
	require.Contains(t, b.String(), "td.textContent=text")
	require.Contains(t, b.String(), "This server permits public URLs only.")
	page.Limits.AllowInternalURLs = true
	b.Reset()
	require.NoError(t, clientTemplates["urldownloads.html"].ExecuteTemplate(&b, "base", page))
	require.Contains(t, b.String(), "Public and internal URLs are permitted by this server.")
}

func TestURLDownloadNavigationUsesProviderPolicy(t *testing.T) {
	u := newDownloadTestUser(t)
	old := urlDownloadManager
	cfg := downloadmanager.DefaultConfig()
	cfg.Enabled = true
	require.NoError(t, InitializeURLDownloads(cfg, t.TempDir(), 0))
	defer func() { StopURLDownloads(); urlDownloadManager = old }()
	req := httptest.NewRequest("GET", "/web/client/files", nil)
	req = req.WithContext(jwt.NewContext(req.Context(), &jwt.Claims{Username: u.Username}, nil))
	s := &httpdServer{}
	data := s.getBaseClientPageData("title.files", "", httptest.NewRecorder(), req)
	require.True(t, data.CanDownloadURLs)
	require.Equal(t, "enabled", data.LoggedUser.Filters.URLDownloads.Access)
	u.Filters.URLDownloads.Access = "disabled"
	require.NoError(t, dataprovider.UpdateUser(&u, dataprovider.ActionExecutorSystem, "", ""))
	data = s.getBaseClientPageData("title.files", "", httptest.NewRecorder(), req)
	require.False(t, data.CanDownloadURLs)
	require.True(t, data.DownloadsEnabled)
}
