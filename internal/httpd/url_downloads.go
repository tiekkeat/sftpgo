// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only
package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/downloadmanager"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

var urlDownloadManager *downloadmanager.Manager

// InitializeURLDownloads starts the exclusively owned queue before HTTP listeners start.
func InitializeURLDownloads(c downloadmanager.Config, base string, shared int) error {
	if !c.Enabled {
		return nil
	}
	if shared != 0 {
		return errors.New("URL downloads require a non-shared single-server deployment")
	}
	m, err := downloadmanager.Open(c, base, downloadmanager.Hooks{Check: checkURLDownload, Import: importURLDownload})
	if err != nil {
		return err
	}
	urlDownloadManager = m
	return nil
}
func StopURLDownloads() {
	if urlDownloadManager != nil {
		_ = urlDownloadManager.Close()
	}
}
func downloadOwner(u dataprovider.User) downloadmanager.Owner {
	return downloadmanager.Owner{Username: u.Username, ID: u.ID, CreatedAt: u.CreatedAt}
}
func downloadUser(r downloadmanager.Record) (dataprovider.User, error) {
	u, e := dataprovider.GetUserWithGroupSettings(r.Owner.Username, "")
	if e != nil {
		return u, e
	}
	if downloadOwner(u) != r.Owner {
		return u, os.ErrPermission
	}
	req := &http.Request{RemoteAddr: r.RemoteAddr, Header: make(http.Header)}
	if e = checkHTTPClientUser(&u, req, "url-download", false, r.OIDC); e != nil {
		return u, e
	}
	if u.Filters.RequirePasswordChange || slices.Contains(u.Filters.WebClient, sdk.WebClientWriteDisabled) {
		return u, os.ErrPermission
	}
	return u, nil
}
func checkURLDownload(r downloadmanager.Record) (downloadmanager.Policy, error) {
	u, e := downloadUser(r)
	if e != nil {
		return downloadmanager.Policy{}, e
	}
	p := urlDownloadPolicy(u, r.RemoteAddr)
	dest := u.GetCleanedPath(r.Job.Destination)
	if !u.HasPerm(dataprovider.PermUpload, path.Dir(dest)) {
		return p, os.ErrPermission
	}
	if ok, _ := u.IsFileAllowed(dest); !ok {
		return p, os.ErrPermission
	}
	if r.Job.State != "importing" {
		c := downloadConnection(u, r.RemoteAddr)
		quota, tq := c.HasSpace(true, false, dest)
		if !quota.HasSpace || !tq.HasUploadSpace() {
			return p, common.ErrQuotaExceeded
		}
		maxSize, _ := c.GetMaxWriteSize(quota, false, 0, false)
		for _, cap := range []int64{maxSize, tq.AllowedULSize, tq.AllowedTotalSize} {
			if cap > 0 && (p.MaxFileSize == 0 || cap < p.MaxFileSize) {
				p.MaxFileSize = cap
			}
		}
	}

	return p, nil
}

// urlDownloadPolicy combines the feature policy with existing upload limits.
func urlDownloadPolicy(u dataprovider.User, remoteAddr string) downloadmanager.Policy {
	p := u.Filters.URLDownloads
	uploadSpeed, _ := u.GetBandwidthForIP(util.GetIPFromRemoteAddress(remoteAddr), "url-download")
	if uploadSpeed > 0 && (p.SpeedLimit == 0 || uploadSpeed*1024 < p.SpeedLimit) {
		p.SpeedLimit = uploadSpeed * 1024
	}
	if u.Filters.MaxUploadFileSize > 0 && (p.MaxFileSize == 0 || u.Filters.MaxUploadFileSize < p.MaxFileSize) {
		p.MaxFileSize = u.Filters.MaxUploadFileSize
	}
	return p
}
func downloadConnection(u dataprovider.User, remote string) *Connection {
	base := common.NewBaseConnection(xid.New().String(), common.ProtocolHTTP, "", remote, u)
	return &Connection{BaseConnection: base, request: &http.Request{Method: http.MethodPost, RemoteAddr: remote, Header: http.Header{"User-Agent": []string{"SFTPGo-URLDownload"}}}}
}
func validateDownloadDestination(dest string) error {
	if !strings.HasPrefix(dest, "/") || dest != path.Clean(dest) || dest == "/" || strings.ContainsAny(dest, "\\\x00") || len(dest) > 4096 {
		return errors.New("destination must be an absolute virtual file path without traversal")
	}
	return nil
}
func checkDownloadDestination(c *Connection, name string) error {
	if !c.User.HasPerm(dataprovider.PermUpload, path.Dir(name)) {
		return os.ErrPermission
	}
	if ok, _ := c.User.IsFileAllowed(name); !ok {
		return os.ErrPermission
	}
	fs, p, e := c.GetFsAndResolvedPath(name)
	if e != nil {
		return e
	}
	if !vfs.CanCreateExclusive(fs) {
		return fmt.Errorf("%w: destination storage does not support create-only URL imports", common.ErrOpUnsupported)
	}
	if _, e = fs.Lstat(p); e == nil {
		return fmt.Errorf("%w: destination already exists; choose another filename", downloadmanager.ErrConflict)
	} else if !fs.IsNotExist(e) {
		return e
	}
	parent, e := fs.Stat(path.Dir(p))
	if e != nil {
		return e
	}
	if !parent.IsDir() {
		return downloadmanager.ErrConflict
	}
	quota, tq := c.HasSpace(true, false, name)
	if !quota.HasSpace || !tq.HasUploadSpace() {
		return common.ErrQuotaExceeded
	}
	return nil
}

// getCreateOnlyWriter uses the normal transfer accounting but never opens an existing target.
// O_EXCL is honored by local/SFTP storage and conditional publication by cloud storage.
func (c *Connection) getCreateOnlyWriter(name string, size int64) (io.WriteCloser, error) {
	if e := checkDownloadDestination(c, name); e != nil {
		return nil, e
	}
	if e := common.Connections.IsNewTransferAllowed(c.BaseConnection); e != nil {
		return nil, e
	}
	fs, p, e := c.GetFsAndResolvedPath(name)
	if e != nil {
		return nil, e
	}
	quota, tq := c.HasSpace(true, false, name)
	maxSize, e := c.GetMaxWriteSize(quota, false, 0, fs.IsUploadResumeSupported())
	if e != nil {
		return nil, e
	}
	if maxSize > 0 && size > maxSize {
		return nil, common.ErrQuotaExceeded
	}
	if (tq.AllowedULSize > 0 && size > tq.AllowedULSize) || (tq.AllowedTotalSize > 0 && size > tq.AllowedTotalSize) {
		return nil, common.ErrQuotaExceeded
	}
	if _, e = common.ExecutePreAction(c.BaseConnection, common.OperationPreUpload, p, name, size, os.O_CREATE|os.O_EXCL); e != nil {
		return nil, os.ErrPermission
	}
	f, w, cancel, e := fs.Create(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, c.GetCreateChecks(name, true, false))
	if e != nil {
		return nil, c.GetFsError(fs, e)
	}
	vfs.SetPathPermissions(fs, p, c.User.GetUID(), c.User.GetGID())
	transfer := common.NewBaseTransfer(f, c.BaseConnection, cancel, p, p, name, common.TransferUpload, 0, 0, maxSize, 0, true, fs, tq)
	return newHTTPDFile(transfer, w, nil), nil
}
func importURLDownload(ctx context.Context, r downloadmanager.Record, stage string, progress func(int64)) error {
	u, e := downloadUser(r)
	if e != nil {
		return e
	}
	c := downloadConnection(u, r.RemoteAddr)
	defer c.CloseFS()
	if e = u.CheckFsRoot(c.ID); e != nil {
		return e
	}
	if e = common.Connections.Add(c); e != nil {
		return e
	}
	defer common.Connections.Remove(c.ID)
	f, e := os.Open(stage)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	writer, e := c.getCreateOnlyWriter(u.GetCleanedPath(r.Job.Destination), info.Size())
	if e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() { markTransferError(writer, context.Canceled); _ = c.SignalTransfersAbort() })
	defer stop()
	var copied int64
	buf := make([]byte, 16*1024)
	for {
		if e = ctx.Err(); e != nil {
			break
		}
		n, re := f.Read(buf)
		if n > 0 {
			wn, we := writer.Write(buf[:n])
			copied += int64(wn)
			progress(copied)
			if we != nil {
				e = we
				break
			}
			if wn != n {
				e = io.ErrShortWrite
				break
			}
		}
		if re != nil {
			if re != io.EOF {
				e = re
			}
			break
		}
	}
	if e != nil {
		markTransferError(writer, e)
	}
	ce := writer.Close()
	if e != nil {
		return e
	}
	return ce
}
func downloadAPIError(w http.ResponseWriter, r *http.Request, e error) {
	status := getMappedStatusCode(e)
	switch {
	case errors.Is(e, downloadmanager.ErrInvalid):
		status = 400
	case errors.Is(e, downloadmanager.ErrNotFound):
		status = 404
	case errors.Is(e, downloadmanager.ErrConflict):
		status = 409
	case errors.Is(e, downloadmanager.ErrLimit):
		status = 429
	case errors.Is(e, downloadmanager.ErrDisabled):
		status = 403
	}
	if status == 500 {
		sendAPIResponse(w, r, nil, "Download operation failed", status)
		return
	}
	sendAPIResponse(w, r, e, "", status)
}
func decodeDownloadRequest(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("invalid download request")
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		return errors.New("invalid download request")
	}
	return nil
}
func (s *httpdServer) registerURLDownloadRoutes(router chi.Router, base string, admin bool) {
	handler := func(w http.ResponseWriter, r *http.Request) { s.handleURLDownloadAPI(w, r, admin) }
	if admin {
		router.With(s.checkPerms(dataprovider.PermAdminViewURLDownloads)).Get(base, handler)
		router.With(s.checkPerms(dataprovider.PermAdminViewURLDownloads)).Get(base+"/{id}", handler)
		router.With(s.checkPerms(dataprovider.PermAdminManageURLDownloads)).Post(base+"/{id}/cancel", handler)
		router.With(s.checkPerms(dataprovider.PermAdminManageURLDownloads)).Delete(base+"/{id}", handler)
	} else {
		router.Get(base, handler)
		router.Get(base+"/{id}", handler)
		router.Post(base, handler)
		router.Delete(base+"/{id}", handler)
		for _, action := range []string{"pause", "resume", "cancel", "retry"} {
			router.Post(base+"/{id}/"+action, handler)
		}
	}
}
func (s *httpdServer) handleURLDownloadAPI(w http.ResponseWriter, r *http.Request, admin bool) {
	m := urlDownloadManager
	if m == nil {
		sendAPIResponse(w, r, nil, "URL downloads are not enabled", 503)
		return
	}
	var owner *downloadmanager.Owner
	var user dataprovider.User
	var e error
	claims, e := jwt.FromContext(r.Context())
	if e != nil {
		downloadAPIError(w, r, os.ErrPermission)
		return
	}
	if !admin {
		user, e = dataprovider.GetUserWithGroupSettings(claims.Username, "")
		if e != nil {
			downloadAPIError(w, r, e)
			return
		}
		if e = checkHTTPClientUser(&user, r, "url-download-api", false, false); e != nil {
			downloadAPIError(w, r, e)
			return
		}
		o := downloadOwner(user)
		owner = &o
	}
	id := chi.URLParam(r, "id")
	if id == "" && r.Method == http.MethodGet {
		jobs := m.List(owner)
		if admin {
			if claims.Role == "" {
				render.JSON(w, r, map[string]any{"jobs": jobs})
				return
			}
			filtered := []downloadmanager.Job{}
			for _, j := range jobs {
				if _, e = dataprovider.UserExists(j.Username, claims.Role); e == nil {
					filtered = append(filtered, j)
				}
			}
			render.JSON(w, r, map[string]any{"jobs": filtered})
			return
		}
		limits := m.Config().Effective(urlDownloadPolicy(user, r.RemoteAddr))
		render.JSON(w, r, map[string]any{"jobs": jobs, "limits": limits, "enabled": user.Filters.URLDownloads.Access == "enabled" && !user.Filters.RequirePasswordChange && !slices.Contains(user.Filters.WebClient, sdk.WebClientWriteDisabled)})
		return
	}
	if id == "" && r.Method == http.MethodPost && !admin {
		var input struct {
			URL         string `json:"url"`
			Destination string `json:"destination"`
		}
		if e = decodeDownloadRequest(w, r, &input); e != nil {
			sendAPIResponse(w, r, e, "", 400)
			return
		}
		if e = validateDownloadDestination(input.Destination); e != nil {
			sendAPIResponse(w, r, e, "", 400)
			return
		}
		c := downloadConnection(user, r.RemoteAddr)
		defer c.CloseFS()
		if e = user.CheckFsRoot(c.ID); e == nil {
			e = checkDownloadDestination(c, user.GetCleanedPath(input.Destination))
		}
		if e != nil {
			downloadAPIError(w, r, e)
			return
		}
		job, e := m.Create(*owner, r.RemoteAddr, input.URL, input.Destination, isLoggedInWithOIDC(r))
		if e != nil {
			downloadAPIError(w, r, e)
			return
		}
		render.Status(r, 202)
		render.JSON(w, r, job)
		return
	}
	record, e := m.Get(id, owner)
	if e != nil {
		downloadAPIError(w, r, e)
		return
	}
	if admin && claims.Role != "" {
		u, ue := dataprovider.UserExists(record.Owner.Username, claims.Role)
		if ue != nil || downloadOwner(u) != record.Owner {
			downloadAPIError(w, r, downloadmanager.ErrNotFound)
			return
		}
	}
	if r.Method == http.MethodGet {
		render.JSON(w, r, record.Job)
		return
	}
	action := path.Base(r.URL.Path)
	if r.Method == http.MethodDelete {
		action = "delete"
	}
	dest := ""
	if action == "retry" {
		var input struct {
			Destination string `json:"destination"`
		}
		if e = decodeDownloadRequest(w, r, &input); e != nil {
			sendAPIResponse(w, r, e, "", 400)
			return
		}
		dest = input.Destination
		if dest == "" {
			dest = record.Job.Destination
		}
		if e = validateDownloadDestination(dest); e != nil {
			sendAPIResponse(w, r, e, "", 400)
			return
		}
		c := downloadConnection(user, r.RemoteAddr)
		defer c.CloseFS()
		if e = checkDownloadDestination(c, user.GetCleanedPath(dest)); e != nil {
			downloadAPIError(w, r, e)
			return
		}
	}
	job, e := m.Action(id, owner, action, dest)
	if e != nil {
		downloadAPIError(w, r, e)
		return
	}
	render.JSON(w, r, job)
}

func getURLDownloadPolicyFromForm(r *http.Request) (downloadmanager.Policy, error) {
	p := downloadmanager.Policy{Access: r.Form.Get("url_download_access")}
	fields := []struct {
		name   string
		target *int64
	}{{"speed_limit", &p.SpeedLimit}, {"max_file_size", &p.MaxFileSize}, {"max_staging_size", &p.MaxStagingSize}}
	for _, f := range fields {
		value := r.Form.Get("url_download_" + f.name)
		if value != "" {
			n, e := strconv.ParseInt(value, 10, 64)
			if e != nil {
				return p, errors.New("invalid URL download limit")
			}
			*f.target = n
		}
	}
	for _, f := range []struct {
		name   string
		target *int
	}{{"max_active", &p.MaxActive}, {"max_pending", &p.MaxPending}} {
		value := r.Form.Get("url_download_" + f.name)
		if value != "" {
			n, e := strconv.Atoi(value)
			if e != nil {
				return p, errors.New("invalid URL download limit")
			}
			*f.target = n
		}
	}
	return p, p.Validate()
}

type clientDownloadsPage struct {
	baseClientPage
	APIURL    string
	Admin     bool
	CanCreate bool
	CanManage bool
	Limits    downloadmanager.Config
}
type adminDownloadsPage struct {
	basePage
	APIURL    string
	Admin     bool
	CanCreate bool
	CanManage bool
	Limits    downloadmanager.Config
}

func (s *httpdServer) handleClientDownloads(w http.ResponseWriter, r *http.Request) {
	data := clientDownloadsPage{baseClientPage: s.getBaseClientPageData("url_downloads.title", webClientDownloadsPath, w, r), APIURL: webClientDownloadsPath + "/jobs", CanManage: true}
	data.CanCreate = data.CanDownloadURLs
	if urlDownloadManager != nil {
		data.Limits = urlDownloadManager.Config()
	}
	renderClientTemplate(w, "urldownloads.html", data)
}
func (s *httpdServer) handleAdminDownloads(w http.ResponseWriter, r *http.Request) {
	data := adminDownloadsPage{basePage: s.getBasePageData("url_downloads.title", webAdminDownloadsPath, w, r), APIURL: webAdminDownloadsPath + "/jobs", Admin: true}
	data.CanManage = data.LoggedUser.HasPermission(dataprovider.PermAdminManageURLDownloads)
	if urlDownloadManager != nil {
		data.Limits = urlDownloadManager.Config()
	}
	renderAdminTemplate(w, "urldownloads.html", data)
}
