# web-samba-tool

Web UI to manage Linux users and Samba users on Ubuntu 24.04.

This tool has been developed with OpenAI Codex. It is to be considered WIP and unstable. It is not intended for production systems at this stage.

It is intended to run on SAMBA hosts inside a LAN, with no direct external access.

## Contributor and Agent Guidance

Repository-specific implementation and safety rules for humans and coding agents are documented in `AGENTS.md`.

## What it does

- Adds Linux users.
- Sets Linux password.
- Adds selected supplemental Linux groups during user creation.
- Updates supplemental Linux groups for existing managed users.
- Creates Samba user/password (`smbpasswd -a`).
- Deletes Linux users (`deluser --remove-home`) and removes Samba users (`smbpasswd -x`) **only for users previously created by this tool**.
- Shows current `/shares` directories with group ownership + mode.
- Requires authenticated login before any management actions.
- Writes audit events (login, create, delete, failures) to a local log file.

This app does **not** edit `/etc/samba/smb.conf`. Samba shares are expected to be managed manually there, and share access is enforced by Linux group membership + filesystem permissions.

Ubuntu uses `deluser` for removal.

## Requirements

- Ubuntu 24.04
- Python 3.12+ (`python3-venv`)
- nginx
- samba (`smbpasswd`, `pdbedit`)

Install packages:

```bash
sudo apt update
sudo apt install -y python3-venv nginx samba
```

## Project setup (inside app user home directory)

Example app user: `sambaadmin`

```bash
cd /home/sambaadmin
git clone https://github.com/bretton/web-samba-tool.git web-samba-tool
cd web-samba-tool
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Sudo setup (required)

The web app runs as an unprivileged user and calls privileged commands via `sudo -n`.

Create sudoers file with `visudo`:

```bash
sudo visudo -f /etc/sudoers.d/web-samba-tool
```

Use:

```sudoers
Defaults:sambaadmin !requiretty
Cmnd_Alias WEBSAMBA_CMDS = \
    /usr/sbin/adduser, \
    /usr/sbin/deluser, \
    /usr/sbin/usermod, \
    /usr/sbin/chpasswd, \
    /usr/bin/smbpasswd, \
    /usr/bin/pdbedit, \
    /usr/bin/getent, \
    /usr/bin/id

sambaadmin ALL=(root) NOPASSWD: WEBSAMBA_CMDS
```

Notes:
- Replace `sambaadmin` with your actual app runtime user.
- Keep command paths exact for Ubuntu 24.04 (`command -v <cmd>` to verify).
- `NOPASSWD` is required because the app uses non-interactive sudo (`sudo -n`).

## Authentication setup (required)

Set these environment variables for the app process:

- `APP_SECRET`: Flask session secret. The app will fail startup if missing or set to a placeholder value.
- `APP_ADMIN_USER`: login username.
- `APP_ADMIN_PASSWORD_HASH`: Werkzeug password hash. The app will fail startup if missing or set to a placeholder value.

Optional hardening/runtime environment variables:

- `APP_AUDIT_LOG` (default: `run/audit.log`)
- `APP_MANAGED_USERS_FILE` (default: `run/managed_users.json`)
- `APP_COMMAND_TIMEOUT_SECONDS` (default: `15`)
- `APP_LOGIN_MAX_ATTEMPTS` (default: `5`)
- `APP_LOGIN_WINDOW_SECONDS` (default: `900`)
- `APP_LOGIN_LOCKOUT_SECONDS` (default: `900`)
- `APP_DISALLOWED_SUPPLEMENTAL_GROUPS` (default: `root,nogroup`; comma-separated group names)

Generate a hash from a plaintext password:

```bash
source .venv/bin/activate
python -c 'from getpass import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass("PASSWORD-GOES-HERE")))'
```

Use the output value as `APP_ADMIN_PASSWORD_HASH`.

If you need to hash a literal password inline (for example one containing `!`), use single quotes around the Python command to avoid Bash history expansion:

```bash
python -c 'from werkzeug.security import generate_password_hash; print(generate_password_hash("P@SSWORD!GOES!HERE"))'
```

## Run with systemd user service

1. Copy service template:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/web-samba-tool.service ~/.config/systemd/user/web-samba-tool.service
```

2. Edit `~/.config/systemd/user/web-samba-tool.service` and replace:
- `APPUSER`
- `APP_SECRET`
- `APP_ADMIN_USER`
- `APP_ADMIN_PASSWORD_HASH`

   Optional: adjust `APP_DISALLOWED_SUPPLEMENTAL_GROUPS` if you want to block additional groups from assignment in the UI/API.

3. Start service:

In order for this to work the users' `.bashrc` needs to have the following added

```
# needed to run systemctl commands
export XDG_RUNTIME_DIR=/run/user/$(id -u)
```

Then either logout and back in, or run `source .bashrc`, then the `systemctl` commands below should work as the user:

```bash
systemctl --user daemon-reload
systemctl --user enable --now web-samba-tool.service
systemctl --user status web-samba-tool.service
```

4. Optional (start on boot without login):

```bash
sudo loginctl enable-linger sambaadmin
```

## nginx setup

1. Copy nginx site:

As root user, or user with sudo privileges:

```bash
cd USERDIR/web-samba-tool
sudo cp deploy/nginx-web-samba-tool.conf /etc/nginx/sites-available/web-samba-tool.conf
```

2. Optionally edit `/etc/nginx/sites-available/web-samba-tool.conf` to change port/IP policy.
   You can uncomment the `allow`/`deny` lines to enforce internal network ranges.

3. Enable site:

```bash
sudo ln -s /etc/nginx/sites-available/web-samba-tool.conf /etc/nginx/sites-enabled/web-samba-tool.conf
sudo nginx -t
sudo systemctl reload nginx
```

By default template listens on `8080`. To run on `80`, uncomment `listen 80;` and remove/adjust `listen 8080;`.

## Direct dev run

```bash
source .venv/bin/activate
python run.py
```

Then open `http://127.0.0.1:5000`.

## Run tests

```bash
python3 -m unittest discover -s tests -v
```

## Operational notes

- Use only on trusted internal networks.
- Configure strong admin credentials and rotate `APP_SECRET` + `APP_ADMIN_PASSWORD_HASH` periodically.
- Failed logins are rate-limited per source IP.
- System command executions time out (default 15 seconds) to avoid hung workers.
- Deletion removes the Linux home directory (`deluser --remove-home`).
- The app can delete only users it created itself (tracked in `APP_MANAGED_USERS_FILE`).
