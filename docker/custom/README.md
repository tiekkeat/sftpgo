# Custom SFTPGo Docker deployment

This deployment builds the current working source, including the URL download manager, into `sftpgo-custom:url-downloads`. It uses Docker Compose, SQLite, a non-root runtime user (UID/GID 1000), and persistent named volumes. The upstream Dockerfiles remain available; this deployment uses its own Go 1.26 builder and Debian runtime. Official optional plugins are not bundled.

All commands below run from `/home/zstack/sftgo-adv/sftpgo`.

## Access and credentials

| Service | Address |
| --- | --- |
| WebAdmin | http://172.60.20.5:18080/web/admin/ |
| WebClient | http://172.60.20.5:18080/web/client/ |
| REST API | http://172.60.20.5:18080/api/v2/ |
| Health | http://172.60.20.5:18080/healthz |
| SFTP | `172.60.20.5:2022` |

The administrator username is `sftpgo-admin`. Its generated password is in `docker/custom/.env`, which has mode `0600` and is excluded from Git and the Docker build context. Read it locally when logging in:

```bash
cat docker/custom/.env
```

Do not paste that file into issue reports or documentation. `docker compose config` without `--quiet` can also print these credentials. Docker administrators can inspect container environment variables. The bootstrap credentials create the administrator only when it does not already exist; editing `.env` does not reset an existing administrator password. Change an existing password in WebAdmin.

Both published ports bind to all IPv4 interfaces (`0.0.0.0`) so LAN PCs can connect directly to this machine at `172.60.20.5`. Localhost access also works on the server. Update the addresses above if the server's IP changes. For access over an SSH tunnel, forward the ports from a workstation:

```bash
ssh -N -L 18080:127.0.0.1:18080 -L 2022:127.0.0.1:2022 zstack@SERVER_HOSTNAME
```

Then open `http://127.0.0.1:18080/web/admin/` on the workstation. Direct web access currently uses HTTP; use the SSH tunnel or configure HTTPS for encrypted web login. Existing services on ports 8080, 8081, 8082, and 8443 are unaffected.

## Build and start

The local `.env` was generated during setup. On a new machine, generate it before starting:

```bash
python3 - <<'PY'
from pathlib import Path
import secrets
p = Path('docker/custom/.env')
if not p.exists():
    p.write_text('SFTPGO_ADMIN_USERNAME=sftpgo-admin\n'
                 'SFTPGO_ADMIN_PASSWORD=' + secrets.token_urlsafe(32) + '\n')
    p.chmod(0o600)
PY
docker compose -f docker/custom/compose.yaml config --quiet
docker compose -f docker/custom/compose.yaml build
docker compose -f docker/custom/compose.yaml up -d
docker compose -f docker/custom/compose.yaml ps
curl --fail http://127.0.0.1:18080/healthz
```

The first build downloads base images and Go modules. Docker caches subsequent builds. Source changes require rebuilding; templates and static assets are also baked into the image. The image includes SQLite and all storage backends, without the optional official plugins.

## Enable users and URL downloads

1. Sign into WebAdmin and create a normal user. The administrator account is separate from transfer users.
2. Use local storage and a home under `/srv/sftpgo/data/<username>`, or configure another supported writable backend. Grant upload permission for the destination folder and enable HTTP access.
3. On the user or group edit page, expand the separate **URL download policy** section, set **Access** to **Enabled**, and save. Configure smaller per-user limits if needed. Earlier builds placed these settings inside the collapsed **ACLs** section.
4. Sign into WebClient as that user. Open **Downloads**, enter a direct public HTTP/HTTPS file URL, choose an existing destination folder and filename, and submit.
5. Monitor fetching and importing progress. Pause/resume fetching, cancel active jobs, or retry failed jobs with a new destination filename. Existing destination files are preserved.

The manager is enabled globally in Compose. Its deployment defaults are:

| Setting | Value |
| --- | ---: |
| Global / per-user active jobs | 8 / 2 |
| Maximum file | 100 GiB |
| Global / per-user staging allowance | 500 GiB / 200 GiB |
| Minimum free staging space | 5 GiB |
| Global / per-user fetch speed | Unlimited (`0`) |
| Global / per-user nonterminal jobs | 1,000 / 100 |
| Automatic retries | 3 |
| Inactive staging / terminal history retention | 7 / 30 days |

The 500 GiB staging value is a ceiling, not preallocated disk. This machine had about 366 GiB available at setup; the free-space floor also applies, and user files share the host disk. Reduce these ceilings to suit actual capacity. Set `SFTPGO_URL_DOWNLOADS__SPEED_LIMIT` or `SFTPGO_URL_DOWNLOADS__SPEED_LIMIT_PER_USER` in Compose to a value in bytes/second, for example `10485760` for 10 MiB/s. Existing user upload limits and quotas still apply. After changing environment settings, use `up -d` to recreate the container; `restart` does not apply changed environment values.

Full policy, storage, security, API, and recovery details are in [the URL download guide](../../examples/url-downloads/README.md). This manager supports one server process, public Internet HTTP(S) sources, and the documented create-only storage backends. HTTP filesystem storage and custom S3 endpoints are excluded.

## Persistent storage

| Docker volume | Container path | Contents |
| --- | --- | --- |
| `sftpgo-custom-state` | `/var/lib/sftpgo` | SQLite provider database, SSH host keys, manager database and private staging, generated application state |
| `sftpgo-custom-files` | `/srv/sftpgo` | Local user home directories and provider backups |

Private staging is separate from user-accessible storage. The configuration file lives in the image at `/etc/sftpgo/sftpgo.json`; Compose environment values override it. Custom external storage and external KMS keys require their own backups. New volumes inherit the runtime user's ownership from the image.

Inspect storage and logs:

```bash
docker volume inspect sftpgo-custom-state sftpgo-custom-files
docker compose -f docker/custom/compose.yaml logs --tail=100
docker compose -f docker/custom/compose.yaml logs -f
docker compose -f docker/custom/compose.yaml exec sftpgo sh -c 'id; df -h /var/lib/sftpgo /srv/sftpgo; du -sh /var/lib/sftpgo/url-downloads /srv/sftpgo/data'
```

Logs rotate at 10 MB with three files. Health checks run every 30 seconds. The container restarts after crashes or Docker daemon restarts under `unless-stopped`; an unhealthy status alone does not trigger a restart.

## Stop, restart, and rebuild

```bash
# Stop while keeping the container and volumes.
docker compose -f docker/custom/compose.yaml stop

# Start the stopped container.
docker compose -f docker/custom/compose.yaml start

# Restart with unchanged configuration.
docker compose -f docker/custom/compose.yaml restart

# Rebuild after editing source and recreate with current configuration.
docker compose -f docker/custom/compose.yaml build
docker compose -f docker/custom/compose.yaml up -d

# Remove the container and network; named volumes remain.
docker compose -f docker/custom/compose.yaml down
```

Do not add `--volumes` to `down` unless you intend to delete application state, staged jobs, and local user files. Save a backup and retain the previous image before upgrading. A provider schema upgrade can prevent an older image from opening the newer database.

## Consistent backup and restore

Stop the service before backing up both volumes so that SQLite, the manager database, staging files, and local user files form a consistent snapshot. Keep backups private; they contain user data and encrypted source URL records. These commands also save deployment settings and the runnable image:

```bash
backup_dir="$(pwd)/docker/custom/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
docker compose -f docker/custom/compose.yaml stop
for volume_name in sftpgo-custom-state sftpgo-custom-files; do
  docker run --rm --user 0:0 --entrypoint tar \
    -v "$volume_name:/source:ro" \
    sftpgo-custom:url-downloads -czf - -C /source . > "$backup_dir/$volume_name.tar.gz"
done
cp docker/custom/.env docker/custom/compose.yaml docker/custom/Dockerfile "$backup_dir/"
docker image save sftpgo-custom:url-downloads | gzip > "$backup_dir/image.tar.gz"
chmod 600 "$backup_dir"/*
docker compose -f docker/custom/compose.yaml start
```

If any backup command fails, inspect the error and restart the service when appropriate. Also save this source tree and any external storage/KMS material.

Restore into **empty** volumes while the service is stopped. Do not extract a snapshot over a running service or an unrelated deployment:

```bash
# Set this to the snapshot directory to restore.
backup_dir=/absolute/path/to/snapshot
gzip -dc "$backup_dir/image.tar.gz" | docker image load
cp "$backup_dir/.env" docker/custom/.env
chmod 600 docker/custom/.env
docker volume create sftpgo-custom-state
docker volume create sftpgo-custom-files
for volume_name in sftpgo-custom-state sftpgo-custom-files; do
  docker run --rm --user 0:0 --entrypoint tar \
    -v "$volume_name:/target" -v "$backup_dir:/backup:ro" \
    sftpgo-custom:url-downloads -xzf "/backup/$volume_name.tar.gz" -C /target
done
docker compose -f docker/custom/compose.yaml up -d
```

Use the snapshot's Compose configuration when recovering its original deployment. Interrupted fetching recovers as paused. Interrupted imports recover as failed and require inspecting the destination before retrying.

## Troubleshooting

- **Port already allocated:** check `ss -ltn` and change only this deployment's published host port in Compose.
- **Unhealthy or restarting:** inspect `docker compose -f docker/custom/compose.yaml logs --tail=100` and the health details with `docker inspect --format '{{json .State.Health}}' sftpgo-custom`.
- **Login rejected:** use the generated administrator credentials for WebAdmin and a normal user for WebClient/SFTP. Changing `.env` does not reset stored passwords.
- **No Downloads action:** enable the user's or primary group's URL download policy and allow uploads/HTTP access.
- **Jobs remain queued:** check active-job limits, staging reservations, retained paused/failed files, quotas, and available disk.
- **Destination conflict:** choose another filename. A failed local/SFTP import may leave a partial file; inspect it before deciding to remove it.
- **Permission denied on volumes:** verify UID/GID 1000 ownership, especially after manual migrations. Avoid recursively changing ownership of unrelated volumes.

## Verification on this machine

The deployment was built and started on October 1, 2026. Verified results:

- Docker Compose configuration validated and the custom image built successfully from the modified working source.
- Running version: `SFTPGo 2.7.99-dev-custom-url-downloads`, with SQLite, PostgreSQL, MySQL, Bolt, S3, GCS, Azure Blob, and metrics enabled.
- Image ID: `sha256:ecc65a4acc6c8f2971028d428cb8f3eaccdef6a00174db5cb7efb7b36e3136a5`; reported image size approximately 266 MB. Rebuilding can produce a new ID.
- Container `sftpgo-custom` reached healthy status, running as UID/GID 1000. Ports were initially published on localhost, then changed to all IPv4 interfaces to support direct LAN access.
- Administrator login and a temporary normal-user login succeeded through the API.
- The temporary user downloaded `https://www.rfc-editor.org/rfc/rfc9110.txt` into local user storage. Fetching and importing completed; the resulting 502,941-byte file contained the expected HTTP Semantics text.
- Port 2022 returned an SSH protocol banner. This check verifies the SFTP listener; it did not perform an authenticated SFTP transfer.
- After a container restart, administrator/user login, completed job history, and the exact downloaded file contents remained available.
- The temporary user's downloaded file, job history, and provider account were removed after verification. No normal transfer user was left provisioned; create your own user in WebAdmin.
- Credentials were confirmed excluded from Git, and Compose validation and `git diff --check` passed.

The backup/restore commands above are operational instructions; a full restore drill was not performed during setup. The container is left running with automatic restart configured.
