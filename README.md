# Debian 13 secure Podman platform

Ansible recipes that turn a fresh Debian 13 machine into a single-node app platform. Public TCP is 22 (ops SSH), 2222 (Forgejo git SSH), and 443 (HTTPS). Everything else that this project installs listens on localhost.

You will get Traefik, an OWASP WAF, Authentik, Forgejo, SigNoz, Wazuh, scheduled Trivy image scanning, a Forgejo Actions runner without Docker-in-Docker, an optional on-box app stack (`svc-scrapecast`), and optional packet sensors (Suricata, Zeek, YAF/SiLK).

If you are new to Ansible, start at **How to deploy**. Architecture, capacity, and the honesty section about packet capture live under **How it works**.

## How to deploy

### Ansible in one page

Ansible is a tool that logs into a Linux machine over SSH and configures it from YAML files.

| Word | Meaning |
|---|---|
| Controller | Your laptop. Ansible runs here. |
| Target | The VPS or Vagrant VM being built. |
| Inventory | `inventory/hosts.yml` or `inventory/vagrant.yml`. IP, SSH user, SSH key. |
| `group_vars/all/main.yml` | Non-secret settings: domain, SSH public key, feature flags. |
| `group_vars/all/vault.yml` | Secrets. Encrypt this file. Never commit it. |
| Playbook | `site.yml`. The ordered list of roles (preflight, dns, base, platform, …). |
| Role | One job, for example "install Traefik" or "lock down sshd". |

This repo uses [uv](https://docs.astral.sh/uv/) so you do not install Ansible globally. `./setup-controller.sh` creates `.venv` and installs Ansible plus Galaxy collections. Prefix commands with `uv run` so they use that environment:

```bash
uv run ansible-playbook site.yml --ask-vault-pass
```

Flags you will see:

| Flag | What it does |
|---|---|
| `-i inventory/vagrant.yml` | Use this inventory instead of the default `inventory/hosts.yml`. |
| `--ask-vault-pass` | Prompt for the password that decrypts `vault.yml`. |
| `--ask-become-pass` | Prompt for the `ops` sudo password. Needed after the first play, once root SSH is gone. |
| `-e name=value` | Override one variable for this run only. |
| `--tags platform` | Run only the roles that have that tag. |

### Tags and maintenance variables

The normal full deployment is intentionally idempotent. Useful focused runs are:

```bash
# Base platform, Wazuh, and live verification
uv run ansible-playbook site.yml --ask-vault-pass --tags platform,wazuh_agent,verify

# Backups and restore workflows (do not include restore during deployment)
uv run ansible-playbook site.yml --ask-vault-pass --tags backup
uv run ansible-playbook site.yml --ask-vault-pass --tags backup_restore,restore
```

Certificate rotation is opt-in. `wazuh_rotate_certificates` defaults to `false`,
so repeated runs preserve the root CA and valid dependent certificates. For a
planned rotation, the platform role archives the existing CA and dependent
certificates, regenerates the complete Wazuh trust chain, and restarts Wazuh:

```bash
uv run ansible-playbook site.yml --ask-vault-pass \
  --tags platform -e wazuh_rotate_certificates=true
```

Rotation replaces the root CA, so every signed Wazuh certificate and trust store
is replaced together. Treat it as a maintenance event; existing external clients
that trust the old CA must be updated.

For a fresh host, one full run is preferred; it includes preflight and all roles:

```bash
uv run ansible-playbook site.yml --ask-vault-pass \
  -e firewall_lockdown_confirm=false
```

The controller talks to one host group, `secure_vps`. `ansible.cfg` already points at `inventory/hosts.yml`.

### What you need

- A Debian 13 target. Public VPS or a local Vagrant VM.
- An SSH public key on the controller (`~/.ssh/id_ed25519.pub` is typical).
- Console/serial access on a VPS. If SSH or the firewall goes wrong, that is how you get back in.
- For a public hostname, a DNS zone you control. Cloudflare is optional but wired up.
- On the controller: `uv`, and for vault generation `openssl` plus `htpasswd` (`apache2-utils` on Debian, `httpd-tools` on Fedora/RHEL). Vagrant plus libvirt if you want a local VM.

The playbook refuses to continue on a host smaller than 8 vCPU, 20 GiB RAM, and 200 GiB disk unless you set `allow_undersized_host: true`. Vagrant inventory sets that for you. A useful production box is more like 12 to 16 vCPU, 32 GiB RAM, and 300+ GiB fast SSD. Wazuh, SigNoz, and the packet sensors are heavy on their own.

### 1. Install Ansible on your laptop

```bash
./setup-controller.sh
```

That is the only controller install step. Re-run it when `requirements.yml` changes.

### 2. Pick names and certificates

Five admin hostnames are built from `base_domain` in `group_vars/all/main.yml`:

`auth`, `git`, `observe`, `security`, `edge`

The product uses the zone apex and `www` (`app_fqdn` / `app_www_fqdn`). `www` redirects to the apex.

How certificates are issued depends on that domain and `traefik_acme_challenge`:

| Where it runs | `base_domain` | `traefik_acme_challenge` | `cloudflare_dns_enabled` | Result |
|---|---|---|---|---|
| Vagrant, throwaway names | `test.local` | ignored | `false` | File CA. Trust `tls/lab-ca.pem` on your laptop. |
| Vagrant or home lab, real zone | `example.net` | `dns` | `true` | Let's Encrypt via Cloudflare TXT records. Works on a private IP. |
| Public VPS | `example.net` | `tls` | `true` or create A records by hand | Let's Encrypt via TLS-ALPN. Let's Encrypt must reach TCP/443. |

`tls` is the default for any domain that is not `.local`. Let's Encrypt's servers look up the name in public DNS and open TCP/443 to that address. A libvirt NAT IP will never answer, so Vagrant with a real zone needs `dns`.

`dns` copies your Cloudflare credential onto `svc-edge` so Traefik can create `_acme-challenge` TXT records. Let's Encrypt never connects to the VM. The same names can later point at a VPS; the certificates stay valid.

Do not publish `AAAA` records. Public listeners are IPv4 only. Do not orange-cloud (proxy) those records. Traefik must see the real client address, and TLS-ALPN cannot complete through Cloudflare's HTTP proxy.

A scoped API token with **Zone.DNS Edit** and **Zone.Zone Read** on that zone is enough. Put it in the vault as `cloudflare_api_token`. A Global API Key plus `cloudflare_email` also works. If the Cloudflare zone name is not `base_domain`, set `cloudflare_zone` (for example zone `example.com` with `base_domain: lab.example.com`).

While you iterate on DNS-01, you can point Traefik at Let's Encrypt staging so you do not burn production rate limits. Uncomment `traefik_acme_ca_server` in `main.yml`. Staging certificates are not trusted by browsers.

### 3. Fill in settings and secrets

**Settings** (`group_vars/all/main.yml`):

- Paste your complete SSH public key line into `admin_authorized_keys`.
- Set `base_domain`, and the certificate/Cloudflare flags from the table above.
- Leave `protect_admin_apps_with_authentik: false` until Authentik proxy providers exist.
- Leave `firewall_lockdown_confirm: false` until SSH on 22 and HTTPS on 443 both work. Open TCP/2222 in the provider security group before you activate nftables, or git SSH dies with the rest of the unexpected traffic.

**Inventory** for a VPS:

```bash
cp inventory/hosts.yml.example inventory/hosts.yml
```

Edit `ansible_host` to the provider IP. First play uses `ansible_user: root` (or whatever the image allows). After the base role, SSH only accepts `ops`.

**Secrets.** Do not copy `vault.yml.example` by hand unless you enjoy hashing passwords. The helper asks for the `ops` sudo password, a temporary web bootstrap password, and contact emails, then generates the rest:

```bash
./generate-vault.sh
```

It prints application passwords on stderr. Save them. Then encrypt:

```bash
uv run ansible-vault encrypt group_vars/all/vault.yml
```

If you use Cloudflare, add `cloudflare_api_token` (or `cloudflare_api_key` and `cloudflare_email`) to `vault.yml` before or after encrypting. `ansible-vault edit group_vars/all/vault.yml` opens the decrypted file in your editor.

Never commit `vault.yml`, `inventory/hosts.yml`, `inventory/vagrant.yml`, runner tokens, registry pull tokens, or `tls/`.

### 4a. Local Vagrant lab

`vagrant up` boots Debian 13 and writes `inventory/vagrant.yml`. It does not run the platform playbook unless you set `VAGRANT_ANSIBLE=1`.

Default libvirt networking is NAT (`192.168.121.0/24`). Your laptop can reach the guest. Other devices on your LAN cannot. For LAN-wide access, create the VM with a bridge (wired NIC or a Linux bridge; Wi-Fi macvtap is often a mess):

```bash
VAGRANT_BRIDGED=1 VAGRANT_BRIDGE=br0 vagrant up
```

**Throwaway `.local` names** (file CA, no Cloudflare):

```bash
./setup-controller.sh
vagrant destroy -f
rm -f inventory/vagrant.yml
vagrant up
uv run ansible-playbook site.yml \
  -i inventory/vagrant.yml \
  --ask-vault-pass \
  -e firewall_lockdown_confirm=false
```

After the base role, sshd only accepts `ops`. Edit `inventory/vagrant.yml` so `ansible_user` is `ops` and `ansible_ssh_private_key_file` is your operator key (`~/.ssh/id_ed25519`). If you leave `ansible_user: ops` in that file and then build a brand-new VM, the first play will fail because `ops` does not exist yet. Delete `inventory/vagrant.yml` before a cold `vagrant up`.

```bash
curl --cacert tls/lab-ca.pem -I https://auth.test.local/
```

`https://edge.test.local/` has no HTTP router. The Traefik dashboard is `/dashboard` and `/api`, and only after `protect_admin_apps_with_authentik` is true.

**Real zone on Vagrant** (Let's Encrypt via DNS-01):

In `main.yml` set `base_domain` to a zone you own, `traefik_acme_challenge: dns`, and `cloudflare_dns_enabled: true`. Put the token in the vault. Then the same `vagrant up` / `ansible-playbook` commands. The dns role publishes A records to the guest IPv4, which may be RFC1918. Browsers on the hypervisor should resolve those names through Cloudflare. Pointing a phone at them still needs a bridged address the phone can route to.

To boot and provision in one step:

```bash
VAGRANT_ANSIBLE=1 vagrant up
```

Later plays:

```bash
VAGRANT_ANSIBLE=1 vagrant provision
VAGRANT_ANSIBLE=1 FIREWALL_LOCKDOWN=1 vagrant provision
```

Without `VAGRANT_ANSIBLE=1`, `vagrant provision` only re-runs the small bootstrap shells.

### 4b. Public VPS

Install a fresh Debian 13 image. Confirm root SSH works. Allow TCP/22, TCP/2222, and TCP/443 in the provider security group. Create the five A records by hand, or set `cloudflare_dns_enabled: true`.

**Pass 1.** Install everything. Do not activate nftables yet:

```bash
uv run ansible-playbook site.yml \
  --ask-vault-pass \
  -e firewall_lockdown_confirm=false
```

The base role creates `ops`, disables root and password SSH, and keeps OpenSSH on TCP/22 with public-key auth only. Traefik binds TCP/443. Forgejo's own SSH binds TCP/2222. Reconnect as `ops@host`. Root SSH will not work after this.

First image pulls and source builds can take 30 to 90 minutes.

From another terminal:

```bash
ssh -p 22 ops@VPS_IPV4
curl -I https://auth.example.net/
curl -u bootstrap https://observe.example.net/api/v1/health
openssl s_client -connect VPS_IPV4:443 -servername git.example.net </dev/null
```

Use your names. With `traefik_acme_challenge: tls`, that last check should show a publicly trusted certificate. SigNoz and Wazuh still use the temporary Basic Auth user `bootstrap` until you finish Authentik.

Change `inventory/hosts.yml` to:

```yaml
ansible_user: ops
ansible_port: 22
ansible_become: true
```

```bash
uv run ansible -m ping secure_vps
```

**Pass 2.** Turn on nftables. You will need the `ops` sudo password:

```bash
uv run ansible-playbook site.yml \
  --ask-vault-pass \
  --ask-become-pass \
  -e firewall_lockdown_confirm=true
```

nftables then drops inbound traffic except loopback, established replies, a little ICMP/ICMPv6, and new TCP/22, TCP/2222, plus TCP/443. Outbound stays open so DNS, NTP, ACME, OIDC, image pulls, updates, and telemetry work.

fail2ban watches host sshd and the Forgejo container journal. A ban lands in fail2ban's own `inet f2b-table`, not `ansible_filter`, so the next firewall apply does not unban everyone. The same action appends the address to the WAF deny list. Console access is still how you get back in if you lock yourself out. Add your own addresses to `fail2ban_ignoreip` if you have a stable source IP.

Two passes feels slow. It exists because a bad nftables policy with no console access is a brick. Setting `firewall_lockdown_confirm=false` later does **not** remove a policy that is already active.

### CIS Debian 13 hardening and safety gates

The base role installs the CIS-oriented login banners, chrony and cron services,
protected cron paths, SSH forwarding/banner/MAC/startup controls, sudo logging,
password-required operator sudo, a restricted `su` group, password-aging defaults,
password quality/history configuration, rsyslog, and the journal-remote package.
Audit records for these policy files and the corresponding journal/filesystem logs
are ingested by the host Wazuh agent.

Three groups of findings are deliberately not forced on a first deployment:

- The native nftables rules are rendered and syntax-checked on every run, but
  `firewall_lockdown_confirm` must remain false until SSH, Forgejo SSH, HTTPS, and
  console recovery are proven. UFW and iptables findings are not applicable to
  this nftables implementation; installing competing firewall managers is unsafe.
  The selected policy defaults inbound and forwarded traffic to deny but leaves
  outbound traffic allowed for DNS, NTP, ACME, package/image pulls, OIDC, and
  telemetry. A literal default-deny-output check therefore remains a deliberate
  availability tradeoff.
- `pam_hardening_confirm` activates pwquality, password history, `use_authtok`, and
  null-password removal only during a console-backed maintenance window. The
  faillock policy is staged but its PAM stack entries remain a documented gap:
  Debian has no safe generic way to merge them into an arbitrarily customized
  provider PAM stack without risking loss of sudo and console authentication.
- `root_account_lock_confirm` locks the local root password only after a tested
  operator sudo session and provider console are available. SSH root login is
  denied independently. Existing unrecognized `NOPASSWD` rules are not deleted;
  the managed operator rule is password-required and loaded late.

`systemd-journal-upload` stays disabled because it requires a separate remote
journal endpoint and would duplicate the security-event path. Wazuh is the
central event sink instead, including rsyslog auth/system logs and the sudo log.
This intentionally leaves the literal journal-upload-active CIS check unmet while
meeting the operational goal without adding an unconfigured network service.

### 5. Authentik accounts and admin apps

Sign in at `https://auth.<domain>` as `akadmin` with `authentik_bootstrap_password`. Username and password already work. You do not need Google or any other OAuth source to use the rest of this stack.

**Local users**

1. **Directory → Groups → New.** Name it `external-users`. Do not give this group superuser permissions or the Authentik Admin interface.
2. **Directory → Users → New User → Internal User.** Set a unique username, display name, and email. Create the user, open it, **Reset password**, and put the user in `external-users`.
3. Keep `akadmin` as break-glass. Create a second admin user in a group that *does* have superuser if you do not want to use `akadmin` daily.

Self-service password reset needs a recovery flow set on **System → Brands**. Until then, reset passwords from the admin user list.

OAuth sources (Google, GitHub, and so on) can wait. When you add one later, create it under **Directory → Federation and Social login**, not under Applications. A Google Web client still needs redirect URI `https://auth.<domain>/source/oauth/callback/google/` and slug `google`.

**Protect SigNoz, Wazuh, and the Traefik dashboard**

1. Create one Authentik proxy provider (forward-auth) and application per external host.
2. Assign them to the embedded outpost. Grant only the intended group.
3. Set the outpost `authentik_host` to `https://auth.<domain>` including the scheme. A bare hostname becomes `https://localhost` in redirects.
4. Put all three applications on the outpost selected list. Authentik's branded "Not Found" page usually means that Host is not assigned to the outpost.
5. On the host, the outpost matches on `Host`:

   ```bash
   curl -sS -o /dev/null -w '%{http_code}\n' \
     -H "Host: observe.<domain>" \
     http://127.0.0.1:19000/outpost.goauthentik.io/auth/traefik
   ```

   401 means the provider is bound. 404 means the Host does not match.

6. Set `protect_admin_apps_with_authentik: true` and rerun `--tags platform,verify`. Traefik then publishes `/outpost.goauthentik.io/` on each protected host (straight to Authentik, not the WAF) and the dashboard at `https://edge.<domain>/dashboard/`. The playbook PATCHes the embedded outpost `authentik_host` and attaches proxy providers whose `external_host` matches observe, security, or edge.

Keep the local application logins as break-glass credentials.

### 6. Forgejo login (optional SSO)

Skip this if you are setting up CI. Authentik OIDC is for people in the browser. The runner already authenticates with its registration token. Jobs get `${{ forgejo.token }}`. None of that talks to Authentik.

Forgejo uses native OIDC so `git` over HTTPS still works. Proxy auth would break that. Local `forgejo_admin_*` is enough to create repositories and enable Actions.

When extra humans need to sign in:

1. In Authentik, create an OAuth2/OpenID provider named `forgejo` and an application bound to it.
2. Redirect URI: `https://git.<domain>/user/oauth2/authentik/callback`
3. In Forgejo, sign in with `forgejo_admin_*`. Under Site Administration → Authentication Sources, add OAuth2 with OpenID Connect discovery. Request `openid profile email`.
4. Test with a non-admin Authentik user before you disable local login.

New Forgejo accounts are restricted, private, and cannot create organizations until an admin elevates them. Host OpenSSH stays `ops` on 22. Git SSH is Forgejo's own server: `ssh://git@git.<domain>:2222/owner/repo.git`. Put keys in the Forgejo UI, not `authorized_keys` on the VPS.

Forgejo Actions can also *issue* OIDC tokens (`enable-openid-connect: true` in a workflow, issuer `https://git.<domain>/api/actions`). That is for talking to AWS, GCP, or a Kubernetes API with short-lived JWTs. Same-host Packages does not need it.

### 7. CI runner

The runner stays unregistered until you create a Forgejo Actions token at the narrowest scope you can live with. Put it in the vault as `forgejo_runner_registration_token` and rerun:

```bash
uv run ansible-playbook site.yml \
  --ask-vault-pass --ask-become-pass \
  --tags runner \
  -e firewall_lockdown_confirm=true
```

Registration talks to Forgejo on `127.0.0.1`, not `https://git.<domain>/`. From this host the public name hairpins through Traefik and the register command never returns.

Ordinary jobs use the `debian-13` label inside a disposable rootless Podman container. They do not get the Podman socket. The default image is `node:24-bookworm`. That is a demo. Override `container.image` in the workflow if the repo is not Node. Job containers resolve `git.<domain>` to the host gateway so checkout does not hairpin the public address.

The `podman-host` label runs `podman --remote` as `svc-runner` and can only control that account's engine. Use it to build and push images. Do not mount another service account's volumes or restart `secure-*` units from a workflow. After `.runner` exists, revoke the one-time token in Forgejo and clear it from the vault.

Workflow code is untrusted code with the rights of `svc-runner`. An example workflow is `examples/forgejo-workflow.yml`.

That example scans the newly built image with the host's pinned Trivy binary before push. JSON and SARIF reports are uploaded as Forgejo job artifacts, then fixable HIGH or CRITICAL findings fail the job. Forgejo does not provide GitHub's Security tab, so SARIF is retained as an artifact rather than uploaded through CodeQL.

CI can only scan images in `svc-runner`'s Podman store. It cannot inspect deployed images owned by `svc-edge`, `svc-wazuh`, or another isolated account. Scheduled `trivy-scan-svc-*.timer` units cover those stores independently after deployment.

### 8. First Actions workflow and Packages

Forgejo Packages is the container registry. Push and pull on `127.0.0.1:13000`, never through `https://git.<domain>/`. Traefik plus the WAF breaks the OCI protocol, and the public name hairpins. `svc-runner` and `svc-scrapecast` get an insecure-registry entry for that loopback address. Other accounts do not.

1. Confirm `forgejo-runner.service` is active and the runner is listed in Forgejo.
2. Create a private repository. Enable Actions on it if the toggle is off.
3. Add `.forgejo/workflows/ci.yml`. Start with a test job on `debian-13`. Override the container image if you need more than Node.
4. For image builds, add a `podman-host` job that logs in with `${{ forgejo.token }}`, builds, and pushes `127.0.0.1:13000/<owner>/<repo>/<image>:<sha>` plus `:main`. Grant `packages: write`.
5. If checkout fails, the runner already maps `git.<domain>` to the host. Check that Traefik is up on `:443` and that the job is not trying to clone via the public IP from a Vagrant NAT.

A throwaway repo with only the test job from `examples/forgejo-workflow.yml` is a good first run before you point a real project at this.

### 9. On-box app (scrapecast)

The product listens on `https://<base_domain>/` and `www` redirects there. Platform admin apps stay on `auth`, `git`, `observe`, `security`, and `edge`.

Runtime is another locked rootless account, `svc-scrapecast`, same restrictions as Authentik or Forgejo. Compose under that user is Postgres plus the three app images from Packages. OTLP goes to the host collector on `127.0.0.1:4318` through a pasta `host.containers.internal` mapping. Traefik is `network_mode: host`, so it uses `127.0.0.1` directly. Do not deploy scrapecast's local SigNoz, OpenObserve, or Kubernetes manifests onto this machine.

The runner never sees that home directory and never uses that Podman socket. CI pushes images. `scrapecast-update.timer` runs `podman-compose pull && up` as `svc-scrapecast` every five minutes and picks up `:main`.

Chicken and egg: the images do not exist until the first successful build job. Ansible creates the user, compose file, and unit anyway. It starts `secure-scrapecast` only after a packages:read token is in the vault *and* `podman-compose pull` succeeds. Until then the playbook prints what is missing and continues.

1. Create `https://git.<domain>/<forgejo_admin_user>/scrapecast.git` and push `main`.
2. Wait for CI to publish `scraper`, `web`, and `evasion` to Packages.
3. In Forgejo, create an access token with package read (not write, not the admin password). Put it in the vault as `scrapecast_registry_pull_token`. `scrapecast_db_password` and `scrapecast_secrets_encryption_key` belong in the vault too (`./generate-vault.sh` makes them on a new vault; an existing vault needs `ansible-vault edit`).
4. Rerun:

```bash
uv run ansible-playbook site.yml \
  --ask-vault-pass --ask-become-pass \
  --tags scrapecast,platform,verify \
  -e firewall_lockdown_confirm=true
```

`--tags platform` refreshes Traefik and the WAF so the apex names are routed. The WAF sends `/api`, `/demo`, and `/rss` to the scraper and `/` to the web UI.

`AUTH_MODE` starts at `off` for a loopback smoke test. That is a synthetic local admin. Put Authentik in front of the *app* (`AUTH_MODE=oidc`, issuer on `https://auth.<domain>/`) before you treat the apex as a public product. That is not the Forgejo login SSO from section 6.

Rollback is retag `:main` in Packages and wait for the timer, or set `scrapecast_image_tag` in `group_vars` and rerun `--tags scrapecast`.

If ModSecurity starts blocking scrape bodies, look at the WAF log and add a CRS exception after you have a real request. Do not guess the rule IDs in advance.

### Day-to-day

```bash
# On the target
systemctl --failed
systemctl status secure-edge secure-auth secure-forgejo secure-signoz secure-wazuh secure-scrapecast
journalctl -u secure-edge --since today
sudo -u svc-forgejo env HOME=/var/lib/svc-forgejo XDG_RUNTIME_DIR=/run/user/2103 podman ps
systemctl status suricata-platform 'zeek@*' 'yaf-*' silk-rwflowpack
ss -lntup
sudo nft list table inet ansible_filter
```

Reapply from the controller:

```bash
uv run ansible-playbook site.yml \
  --ask-vault-pass --ask-become-pass \
  -e firewall_lockdown_confirm=true
```

Useful tags: `preflight`, `dns`, `base`, `platform`, `trivy`, `telemetry`, `sensors`, `wazuh_agent`, `runner`, `scrapecast`, `backup`, `restore`, `verify`.

## How it works

### What is installed

| Boundary | Components | Exposure |
|---|---|---|
| Host | nftables, OpenSSH, native OTel Collector, native Wazuh agent | `22/tcp`, `2222/tcp`, and `443/tcp`; ICMP/ICMPv6 stays allowed |
| `svc-edge` | Traefik, ACME, security headers, rate limiting, OTLP | `0.0.0.0:443` |
| `svc-waf` | Nginx + ModSecurity + OWASP Core Rule Set | `127.0.0.1:18090` |
| `svc-auth` | Authentik server, worker, PostgreSQL | `127.0.0.1:19000`; metrics on `127.0.0.1:19300` |
| `svc-forgejo` | Forgejo, SQLite | `127.0.0.1:13000` for HTTP; `0.0.0.0:2222` for git SSH |
| `svc-signoz` | SigNoz, one ClickHouse, Keeper, PostgreSQL, ingester | UI and OTLP on loopback only |
| `svc-wazuh` | Wazuh manager, indexer, dashboard | enrollment, agent, API, dashboard on loopback |
| `svc-runner` | Forgejo Runner + that user's rootless Podman socket | no public listener |
| `svc-scrapecast` | scrapecast Postgres + app images from Forgejo Packages | `127.0.0.1:43147` and `:43148`; HTTPS apex only |
| Sensor users | Suricata, Zeek LTS, YAF + SiLK | capture only; no login or sudo |

Each rootless account has a locked password, `/usr/sbin/nologin`, no extra groups, no sudo, a private `0700` home, and a non-overlapping subordinate UID/GID range. Container root is that unprivileged host account. Authentik, SigNoz, and Wazuh share one account per stack because their supported Compose design needs a shared network and volumes. Independent components get their own account.

Traefik does not get a Podman socket. Routes come from a static, read-only file. WAF traffic goes through the official OWASP CRS image, not Traefik's experimental Coraza WASM plugin. On `git.<domain>`, CRS skips restricted-extension and restricted-file rules so Forgejo can show repository files such as `.sh`, `.cfg`, and `.gitignore`. Hidden `/.git` paths stay denied. Git over HTTPS smart HTTP stays blocked; clone on SSH port 2222.

OpenSSH accepts public-key authentication for `ops` only. Root login and password authentication are disabled. `git@host:22` is not a host account. Clone with `ssh://git@git.<domain>:2222/owner/repo.git`.

### Why TLS-ALPN needs a public IP

`traefik_acme_challenge: tls` uses Let's Encrypt TLS-ALPN-01. Let's Encrypt looks up the hostname in public DNS, connects to that IP on TCP/443 from the internet, and completes a TLS handshake using the protocol `acme-tls/1`. Traefik presents a short-lived certificate for that name. If the handshake succeeds, Let's Encrypt issues the real certificate.

A private address (typical Vagrant NAT) is not reachable from those servers. DNS-01 skips the connection: Traefik writes a TXT record through Cloudflare, Let's Encrypt reads that record, and the host can stay off the internet.

### Telemetry

| Signal | Source |
|---|---|
| Latency, traffic, errors | Traefik OTLP metrics, traces, and access logs to the host collector |
| Saturation | Host CPU/memory/disk/network, WAF stub_status, and per-account Podman container stats |
| Logs | Direct OTLP application/access logs plus warning/error journals for platform and sensor service health |
| App telemetry | Traefik OTLP logs over HTTP to `127.0.0.1:4318/v1/logs`. Metrics and traces over gRPC to `127.0.0.1:4317`. Scrapecast uses pasta `host.containers.internal:4318`. Prometheus scrape of Forgejo and Authentik. Authentik and Forgejo have no native traces. The CRS image has no request tracing module. |

The host collector is the only app OTLP ingest. It queues and exports to SigNoz on loopback gRPC `127.0.0.1:14317`. Raw IDS, authentication, firewall, package-change, and WAF events are intentionally excluded. Do not expose unauthenticated OTLP. For another host, use a mutually authenticated collector or a VPN and add a firewall rule on purpose.

Foundry's `replicas` field is 0-based: `replicas: 0` is one ClickHouse. `replicas: 1` starts a second node, and that pair will OOM an 8 GiB host during `system.metric_log` merges. The playbook caps the remaining node (`mem_limit` plus `max_server_memory_usage`) and deletes the ClickHouse and Keeper volumes when it sees the extra replica, then reforges Compose so only `clickhouse-0-0` remains. `podman-compose up` hangs forever on Foundry's `depends_on: service_healthy`, so the casting rewrites ClickHouse deps to `service_started` and vendors `histogramQuantile` instead of wget from GitHub at start. It waits for `SHOW CREATE TABLE signoz_traces.distributed_signoz_index_v3` before treating SigNoz as ready. The UI can listen before that table exists; that is the `failed to get tbl statement` error. Undersized hosts get a 4 GiB swap file. Postgres (users, dashboards) stays. Set `signoz_reset_telemetrystore: true` once if the store is already a single node with leftover two-replica schema.

The playbook upserts a small SigNoz alert set when `signoz_api_token` is in the vault: root and `/var/lib` disk, ClickHouse container memory, otelcol export failures from the operations journal, failed `secure-*`/sensor units, and Traefik 5xx plus p95. Channels start empty, so they show in the UI until you attach a notifier. Retention is still yours to set. Security detections stay in Wazuh.

### Packet visibility and Wazuh

Default `sensor_interfaces` is the WAN NIC plus `lo`. That captures encrypted WAN traffic and the decrypted loopback path to backends. Add extra host-visible bridge or veth names yourself.

Rootless Podman uses a per-user network. Those container-to-container links are not host NICs, so Suricata, Zeek, and YAF on the host do not see every database packet on those private links. The playbook does not pretend otherwise. Full east-west inspection means a rootful bridge with a tap, eBPF, or a dedicated sensor host. That is a different trust model.

Capturing WAN and loopback duplicates observations. Size disks accordingly.

A native Wazuh agent on the host collects filtered SSH, sudo, identity, auditd, fail2ban, nftables, package, selected container, IDS, and WAF events. It does not forward every container or journal record. FIM covers host security policy, systemd, package/repository, sensor, telemetry, Trivy, rootless runtime, and stack configuration. There is no privileged Wazuh process inside each vendor container. If a control literally requires an agent PID in every container, this design does not meet that wording.

Wazuh 5.0.0-beta5 dropped classic `etc/rules` XML, `wazuh-logtest`, and `PUT /logtest`. The 4.x files under `roles/wazuh_agent/templates/platform-security-rules.xml.j2` and `roles/trivy/templates/trivy-rules.xml.j2` are a mapping of the old ids only; the manager does not evaluate them. Live detections are Sigma in `roles/wazuh_agent/files/engine/rules.json`, published Draft → Test → Custom through the indexer Content Manager. Ansible proves a representative event against Test with `/_plugins/_content_manager/logtest` before promoting to Custom.

Use **Threat Hunting** on `wazuh-findings-v5-*`, not `wazuh-alerts-*`. Filter on rule title or `sigma_id` (`platform-100400`, `trivy-100307`). Native journald metadata is used by the agent-side filters; Wazuh forwards those records in syslog form, so investigation uses the decoded program/message fields rather than `CONTAINER_NAME` or `_SYSTEMD_UNIT`.

- `Host firewall dropped an inbound packet` (`platform-100400`) for nftables drops. Frequency correlation (old 100401) does not exist in 5.x.
- `Host authentication or privilege failure` and `Identity or source-control authentication failure` for SSH, sudo, Authentik, and Forgejo.
- `ModSecurity CRS detected or blocked a request` and Traefik 401/403/429 / TLS handshake errors.
- Suricata alert/anomaly and Zeek notice/intel/signature/metadata titles for network IDS.
- `A host security control reported a failure` for sshd/auditd/fail2ban health.
- `Trivy HIGH finding`, `Trivy CRITICAL finding`, and `Trivy scan failed`.

Use Wazuh's dedicated **File Integrity Monitoring**, **Configuration Assessment**, and **Vulnerability Detection** views for those datasets. Wazuh indexes meaningful rule matches rather than every raw network flow. SiLK flow records remain queryable with SiLK tools under `/var/lib/silk/data`; they are not text logs and should not be copied into Wazuh. Existing fail2ban/nftables actions remain the only automatic blocking path; Wazuh active response is not enabled.

Apply the complete routing boundary with `ansible-playbook site.yml --tags base,platform,telemetry,sensors,wazuh_agent,verify`. The base tag installs auditd and deterministic Podman journal tags; the other tags update both collectors, sensor outputs, engine content, and end-to-end checks.

For the publisher/login-outcome and ClickHouse export fixes on an existing deployment, use:

```bash
uv run ansible-playbook site.yml --tags platform,wazuh_agent,backup,verify --ask-vault-pass --ask-become-pass
```

Preflight runs automatically. Do not select `restore` during deployment. Publisher code, configuration, and progress now live in root-only `/usr/local/libexec/platform-wazuh/`, `/etc/platform-wazuh/`, and `/var/lib/platform-wazuh/`. Legacy stack `engine/` files remain untouched and unused. The existing CA is pinned once into the protected configuration directory; subsequent runs do not silently replace it. Credentials and CA identities are not rotated.

Publishing discovers resources through authenticated Content Manager searches rather than trusting legacy UUID state. Before changing content, it runs audit login fixtures against the discovered Standard `auditd` integration. It then tests managed content in Test and repeats Standard/Custom production checks after promotion. Failed, missing, unknown, and contradictory outcomes must never have a successful-authentication title. Wazuh Standard rules are read-only: if the installed vendor rule still mislabels an event, deployment stops with the offending rule IDs/titles. No authentication events are suppressed and no vendor system indices are modified. Obtain a supported vendor correction before retrying. Existing indexed findings are unchanged.

`--tags verify` performs live fixtures; a progress file alone is not evidence of verification. Local contract/render tests do not replace live Wazuh fixture execution or restoring an archive into an isolated ClickHouse instance. Both are required before declaring production acceptance complete.

Trivy scans the image IDs used by running containers once per rootless account. Each account gets a private cache and can access only its own Podman socket. Raw reports stay under `/var/log/trivy/<account>/`; Wazuh receives normalized JSON events for new and resolved findings, scan summaries, and failures. Hunt with the Trivy titles above. Initial scans are staggered, and later scans run daily with randomized delay.

Apply the manager rules, scanners, and agent reader together with `--tags platform,trivy,wazuh_agent`. To scan one account immediately, run `sudo systemctl start trivy-scan-svc-wazuh.service` (replace the account suffix as needed). After all initial timers have fired, set `trivy_verify_scan_results: true` and run `--tags verify` to require a completed report from every account.

Suricata sends alerts, anomalies, and selected investigation metadata to Wazuh. Zeek sends only notices, intelligence/signature matches, weird activity, and selected file/TLS/SSH metadata. SiLK and YAF operational failures stay in the warning-level SigNoz health feed; raw flow records remain in SiLK. Calling every Zeek or SiLK record an alert would be wrong.

Suricata's yaml has no CPU-percent cap. The default `threads: auto` starts one worker per core and will fill a 4 vCPU lab. This playbook sets `suricata_af_packet_threads: 1` (one worker per capture interface) and `suricata_detect_thread_ratio: 0.5` in `/etc/suricata/platform-local.yaml`. Raise the thread count on a large VPS if `eve-security.json` or the service journal shows kernel drops.

### Supply chain

Review release notes before changing a pinned version or checksum. Keep Wazuh manager and agent on the same version. Changing a Wazuh indexer identity after initialization needs Wazuh's security-admin procedure; editing Compose and the mounted hash is not enough.

Standalone binaries and source archives are checksum-pinned. Repository keys come from official endpoints. Most OCI images use version tags, not digests. For strict provenance, mirror and sign internally, then replace the URLs and image references.

### Backups and recovery

Off-box copies use resticprofile 0.33.1 plus Debian restic, destination Backblaze B2 over the S3 API (`s3:s3.<region>.backblazeb2.com/<bucket>/platform`). The native `b2:` backend hangs on this host. There is no backup web UI.

Set `backup_offsite_enabled: true` and put `backup_b2_key_id`, `backup_b2_application_key`, `backup_restic_password`, `backup_b2_bucket`, and `backup_b2_endpoint` in the vault. Ansible then installs dump hooks, resticprofile YAML, and systemd timers. A run-before hook writes recoverable artifacts to `/var/lib/platform-backup/staging`: Authentik and scrapecast `pg_dump`, Authentik media/certificates, SigNoz Postgres, every non-system ClickHouse database, `acme.json`, Wazuh manager and stack configuration (including its TLS material), and a cleanly stopped Wazuh Indexer data archive. Forgejo is briefly stopped while its complete data and configuration volumes are archived, including repositories, LFS, attachments, Actions artifacts, and packages. Required services or exports failing makes the backup fail, so retention pruning cannot turn an incomplete staging set into a green backup. Only paths below `/var/lib/platform-backup` are accepted for destructive staging/restore cleanup.

```bash
uv run ansible-playbook site.yml --tags backup --ask-vault-pass --ask-become-pass
```

Restore is a separate, harder gate. It writes the latest snapshot to `/var/lib/platform-backup/restore` and stops. You copy dumps onto a staging host or into new volumes by hand.

```bash
uv run ansible-playbook site.yml --tags restore --ask-vault-pass --ask-become-pass \
  -e backup_restore_confirm=true
```

Also keep the encrypted vault on the controller. `/var/lib/silk/data` is optional (`backup_include_silk`). Provider snapshots stay crash-consistent only.

If SSH or TLS fails after lockdown, use the provider console. Restore a corrected `/etc/nftables.conf` and restart nftables. Do not re-enable root or password SSH as routine recovery.

## Primary references

- [Debian 13 Podman](https://packages.debian.org/trixie/podman) and [OpenSSH](https://packages.debian.org/trixie/openssh-server)
- [Traefik ACME](https://doc.traefik.io/traefik/https/acme/), [entrypoints](https://doc.traefik.io/traefik/routing/entrypoints/), [tracing](https://doc.traefik.io/traefik/reference/install-configuration/observability/tracing/), [metrics](https://doc.traefik.io/traefik/reference/install-configuration/observability/metrics/), [logs](https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/)
- [OWASP CRS container images](https://github.com/coreruleset/modsecurity-crs-docker)
- [Authentik Compose](https://docs.goauthentik.io/install-config/install/docker-compose/), [Google source](https://docs.goauthentik.io/users-sources/sources/social-logins/google/cloud/), [proxy providers](https://docs.goauthentik.io/add-secure-apps/providers/proxy/)
- [Forgejo rootless](https://forgejo.org/docs/v15.0/admin/installation/docker/) and [Runner with rootless Podman](https://forgejo.org/docs/v15.0/admin/actions/installation/binary/)
- [Forgejo Packages](https://forgejo.org/docs/v15.0/user/packages/) and [Actions OIDC](https://forgejo.org/docs/v15.0/user/actions/security-openid-connect/)
- [SigNoz Docker](https://signoz.io/docs/install/docker/) and [Podman metrics](https://signoz.io/docs/metrics-management/opentelemetry-podman-metrics/)
- [Wazuh agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html), [container deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html), [password rotation](https://documentation.wazuh.com/current/deployment-options/docker/changing-default-password.html), [capacity](https://documentation.wazuh.com/current/quickstart.html)
- [Suricata AF_PACKET](https://docs.suricata.io/en/latest/capture-hardware/af-packet.html), [Zeek](https://docs.zeek.org/en/current/install.html), [YAF](https://tools.netsa.cert.org/yaf/yaf.html), [SiLK sensor.conf](https://tools.netsa.cert.org/silk/sensor.conf.html)
- [OTel Podman receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/podmanreceiver/README.md) and [journald receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/journaldreceiver/README.md)
- [Cloudflare API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/), [lego Cloudflare](https://go-acme.github.io/lego/dns/cloudflare/), [Ansible cloudflare_dns](https://docs.ansible.com/ansible/latest/collections/community/general/cloudflare_dns_module.html)
