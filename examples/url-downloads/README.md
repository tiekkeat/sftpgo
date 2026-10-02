# URL download manager

The web client can fetch direct HTTP/HTTPS URLs into a user's existing storage folders. Users see separate fetching and importing progress and can pause, resume, cancel, retry, or remove terminal history. Files with existing names are preserved. Signed URLs work; interactive logins, source authentication headers, FTP/SFTP sources, torrents, and media extraction are not supported.

## Enable and grant access

The feature is disabled by default. Enable the `url_downloads` section in `sftpgo.json`, choose durable, writable paths, and restart SFTPGo:

```json
{
  "url_downloads": {
    "enabled": true,
    "database_path": "/var/lib/sftpgo/url-downloads/jobs.db",
    "staging_path": "/var/lib/sftpgo/url-downloads/staging"
  }
}
```

Unspecified settings use the defaults below. Equivalent environment variables include `SFTPGO_URL_DOWNLOADS__ENABLED=true`, `SFTPGO_URL_DOWNLOADS__DATABASE_PATH`, and `SFTPGO_URL_DOWNLOADS__STAGING_PATH`. Relative paths resolve against the SFTPGo configuration directory. Mount the database and staging directory on persistent Docker volumes, outside users' storage roots. The service account must be able to create and write both paths. The staging directory is private to this manager.

Enable access in WebAdmin's user or group edit form by expanding the separate **URL download policy** section and setting **Access** to **Enabled**. REST representations use a user's `filters.url_downloads` or a primary group's `user_settings.url_downloads`:

```json
{
  "access": "enabled",
  "max_active": 2,
  "max_pending": 20,
  "speed_limit": 10485760,
  "max_file_size": 107374182400,
  "max_staging_size": 214748364800
}
```

Access accepts `inherit`, `enabled`, or `disabled`. Unset access inherits from the primary group and is otherwise disabled. Explicit user values override primary-group values. Zero limits inherit; global ceilings always apply. Secondary and membership groups do not grant access. Speed limits use **bytes per second**, unlike SFTPGo's existing bandwidth fields, which use KiB/s.

Users also need upload permission for the destination directory and writable HTTP/web-client access. Filename restrictions, account expiration, IP restrictions, storage quotas, upload quotas, upload hooks, bandwidth restrictions, and transfer-count limits still apply. Jobs reload user and group policy before execution, during execution, and before import. Revoking access stops affected jobs; disabled feature access does not prevent inspecting or canceling a user's existing jobs while their account remains authorized for HTTP access.

## Server settings

| Key | Default | Meaning |
| --- | ---: | --- |
| `enabled` | `false` | Global enable switch |
| `allow_internal_urls` | `true` | Permit internal destinations for all users authorized to download |
| `max_active` / `max_active_per_user` | 8 / 2 | Fetching and importing jobs share these slots |
| `max_pending` / `max_pending_per_user` | 1,000 / 100 | Nonterminal jobs, including paused jobs |
| `max_file_size` | 107374182400 | 100 GiB per file |
| `max_staging_size` | 536870912000 | 500 GiB aggregate staging reservations |
| `max_staging_per_user` | 214748364800 | 200 GiB per user |
| `min_free_space` | 5368709120 | Preserve 5 GiB of free staging disk |
| `speed_limit` / `speed_limit_per_user` | 0 / 0 | Aggregate fetch caps; zero means unlimited |
| `retry_max` | 3 | Automatic retries after retryable source failures |
| `connect_timeout` / `header_timeout` / `idle_timeout` | 15 / 30 / 120 | Seconds; idle time measures network reads rather than rate-limit waits |
| `max_redirects` | 5 | Maximum redirect hops |
| `staging_retention_hours` | 168 | Remove inactive queued/paused/failed staging after seven days |
| `history_retention_hours` | 720 | Remove terminal history after thirty days |
| `allowed_ports` | `[80,443]` | Administrator-approved public destination ports |
| `allowed_hosts` / `denied_hosts` | `[]` / `[]` | Optional host restrictions; deny takes precedence |

Internal URLs are enabled by default, including when `allow_internal_urls` is omitted. This is a server-wide network setting, not a grant of download access: user/primary-group access must still be enabled. To block internal URLs for everyone, set `url_downloads.allow_internal_urls` to `false`, or add this environment setting in Portainer/Compose and recreate the container:

```yaml
SFTPGO_URL_DOWNLOADS__ALLOW_INTERNAL_URLS: "false"
```

When enabled, every reachable internal unicast destination is permitted without an IP or hostname allowlist: LAN, Docker networks, localhost, IPv6 private addresses, and link-local/metadata endpoints. Internal HTTP/HTTPS URLs can use any port from 1–65535 and bypass `allowed_hosts`. Explicit `denied_hosts` rules always apply. For example, `http://192.168.1.20:8080/file.zip` and `http://fileserver:9000/file.zip` work if the container can reach and resolve those hosts. Localhost refers to the SFTPGo container itself; use a Docker service name or a reachable host address for another server. Scoped IPv6 URLs (containing an interface zone) remain unsupported.

Public destinations retain `allowed_ports` and `allowed_hosts` restrictions. Host rules accept exact names or `*.example.com`, which matches subdomains, not the bare domain. With internal URLs disabled, the original public-only address restrictions apply, including rejection of private, loopback, link-local, reserved, and metadata addresses. Unspecified, multicast, and broadcast destinations are rejected in either mode. Every DNS answer and redirect is checked; a mixed DNS answer set is rejected if any address violates the applicable policy. With internal access enabled, hostname-dependent decisions are deferred until DNS resolution and failures appear in job status.

Connections dial validated IP addresses directly while retaining normal TLS hostname verification, even for internal HTTPS servers. The manager does not inherit hook credentials, cookies, TLS bypass settings, or environment proxies. This setting requires a service restart; it does not add source login flows or custom authentication headers.

Unknown-length jobs initially reserve their maximum permitted size within configured staging allowances. Once response headers provide a length, reservations shrink. Physical disk allocation grows with received data; the free-space floor is checked during writes. When slots or staging reservations are unavailable, jobs remain queued. Failed and paused jobs retain staged data and consume staging allowance until removed or expired.

## Storage, progress, and recovery

Fetching stages a complete file locally. Resumption requires a strong ETag and the same effective source URL, followed by a valid partial response. Otherwise the manager restarts safely from zero or reports a source error. Unknown-length downloads show indeterminate progress.

Import uses normal upload accounting: storage and upload transfer quotas are charged by import, including ordinary failed-import accounting. Staging has its own limits. Existing upload bandwidth limits also constrain fetching, and their ordinary throttling remains active during import. Fetch caps aggregate across jobs belonging to the same user. Fetching and importing are distinct phases; pause applies to fetching, while import can be canceled and retried from its complete staged file.

Create-only imports support local storage, encrypted local storage, SFTP, AWS S3, Google Cloud Storage, and Azure Blob Storage. Cloud publication uses backend preconditions. HTTP filesystem imports and custom S3 endpoints are rejected because their exclusive-create guarantees are not established. Local and SFTP imports may expose their newly created file while import progresses, independently of the server's normal atomic-upload setting. Failed imports can leave a partial destination; inspect it and retry with a different filename. The manager never removes or overwrites an existing destination to make a retry succeed.

Queued and paused jobs persist. Interrupted fetching recovers as paused. An interrupted import recovers as failed: inspect the destination before retrying, because the backend might already have published the file. Completed and canceled jobs erase their encrypted source URL. Deleting history never deletes completed destination files. Cancellation is best effort if backend publication has already completed.

Only one process may own a manager database. Shared-provider deployments are rejected when the feature is enabled. Job state is separate from SFTPGo provider dumps: back up the manager database, staging, user data provider, and KMS configuration together while the service is stopped. Account deletion/recreation does not grant access to the deleted account's jobs.

## API

Authenticated user endpoints:

| Method | Path | Operation |
| --- | --- | --- |
| POST | `/api/v2/user/url-downloads` | Create with `{"url":"https://example.com/file.zip","destination":"/incoming/file.zip"}`; returns 202 |
| GET | `/api/v2/user/url-downloads` | List owned jobs and effective limits |
| GET | `/api/v2/user/url-downloads/{id}` | Job details |
| POST | `/api/v2/user/url-downloads/{id}/pause` | Pause queued/fetching work |
| POST | `/api/v2/user/url-downloads/{id}/resume` | Queue a paused job |
| POST | `/api/v2/user/url-downloads/{id}/cancel` | Cancel nonterminal work |
| POST | `/api/v2/user/url-downloads/{id}/retry` | Retry failed work; body `{}` or `{"destination":"/incoming/new-name.zip"}` |
| DELETE | `/api/v2/user/url-downloads/{id}` | Remove terminal history and staging |

Jobs report `state`, `phase`, `bytes_fetched`, `bytes_imported`, `total_bytes`, `speed`, `eta_seconds`, timestamps in milliseconds, attempts, and sanitized error/notice text. A total or ETA of `-1` means unknown. Source displays omit query strings; full source URLs remain encrypted in the manager database.

Administrator endpoints use `/api/v2/url-downloads`: list/detail require `view_url_downloads`; cancel/delete require `manage_url_downloads`. They respect administrator role boundaries. Existing `*` administrator permission includes both. Browser routes use cookie authentication and CSRF validation, and follow the configured HTTP base URL.

Prometheus metrics expose queued and active jobs, staged bytes, fetched bytes including retries, and failures under the `sftpgo_url_downloads_` prefix. Metrics contain no URL or username labels. Begin with a small opt-in group and watch staging usage, throughput, and failure rates.
