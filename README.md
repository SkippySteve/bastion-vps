# Debian 13 secure Podman platform

Ship to production, learn fast. Staging environments can't replicate production reality. We're now observing real adversarial activity, live traffic patterns, and actual bottlenecks as they happen.

Ansible recipes that turn a fresh Debian 13 machine into a hardened, single-node application and security platform.

You will get Traefik, a CrowdSec v1.8.1 AppSec WAF and threat intelligence engine (or optional ModSecurity + CRS), Authentik identity management, Forgejo git hosting, SigNoz observability, Wazuh SIEM/XDR, scheduled Trivy container image scanning, a Forgejo Actions runner with rootless Podman, an optional on-box application stack (`svc-scrapecast`), and optional network packet sensors (Suricata IDS, Zeek NSM, YAF/SiLK IPFIX flow logging).

Deployment is designed to be streamlined and efficient: in normal circumstances it requires only a **single automated playbook execution**. For ongoing maintenance and development, finely scoped execution tags let you update individual services (such as Suricata rules or firewall filters) in seconds rather than waiting for multi-role rebuilds.

Public TCP exposure is restricted to ports `22` (ops OpenSSH), `2222` (Forgejo git SSH), and `443` (HTTPS). Everything else installed by this project listens strictly on localhost.

---

## Quickstart: Deploying the platform

### Ansible in one page

Ansible is an automation tool that connects to a target Linux machine over SSH and configures it from declarative YAML playbooks.

| Term | Meaning |
|---|---|
| **Controller** | Your local laptop or workstation where Ansible runs. |
| **Target** | The Debian 13 VPS or Vagrant VM being configured. |
| **Inventory** | `inventory/hosts.yml` (production VPS) or `inventory/vagrant.yml` (local VM). Defines target IP, SSH user, and credentials. |
| `group_vars/all/main.yml` | Non-secret platform settings: domain, SSH public keys, hardware sizing, and feature flags. |
| `group_vars/all/vault.yml` | Encrypted secrets file. Never commit this plaintext to version control. |
| **Playbook** | `site.yml`. The top-level orchestration playbook ordering all roles. |
| **Role** | A modular unit of configuration (e.g. `base`, `platform`, `sensors`, `firewall`). |

This repository uses [uv](https://docs.astral.sh/uv/) to manage dependencies without touching your global Python environment. `./setup-controller.sh` installs `uv`, configures `.venv`, and downloads required Ansible Galaxy collections. Prefix playbook commands with `uv run` to execute within this managed environment:

```bash
uv run ansible-playbook site.yml --ask-vault-pass
```

Common command-line flags:

| Flag | Purpose |
|---|---|
| `-i <inventory>` | Specify inventory path (defaults to `inventory/hosts.yml` via `ansible.cfg`). |
| `--ask-vault-pass` | Prompts for the password to decrypt `group_vars/all/vault.yml`. |
| `--ask-become-pass` | Prompts for the `ops` user sudo password (needed for subsequent plays once root SSH is disabled). |
| `-e key=value` | Override a variable for this execution only (e.g. `-e firewall_lockdown_confirm=true`). |
| `--tags <tag,...>` | Run only roles or tasks matching the specified tags (e.g. `--tags firewall` or `--tags suricata`). |

---

### Prerequisites & Hardware Sizing

- **Target OS**: Fresh Debian 13 (Trixie) installation (public VPS or local Vagrant VM).
- **SSH Key**: An Ed25519 public key on your controller (`~/.ssh/id_ed25519.pub`).
- **Domain & DNS**: A public domain zone for production TLS certificates (Cloudflare DNS automation supported).
- **Controller Tools**: `uv`, `openssl`, and `htpasswd` (`apache2-utils` on Debian/Ubuntu, `httpd-tools` on RHEL/Fedora).
- **VPS Console Access**: Cloud serial/web console access is recommended as a safety precaution before activating firewall lockdown.

#### Sizing requirements
This platform runs production-grade observability (SigNoz/ClickHouse), SIEM (Wazuh manager/indexer), and full packet analysis engines (Zeek, Suricata, SiLK).
- **Production VPS**: 12–16 vCPUs, 32 GiB RAM, 300+ GiB NVMe SSD.
- **Minimum Floor**: 8 vCPUs, 20 GiB RAM, 200 GiB disk.
- **Lab / Undersized Hosts**: Set `allow_undersized_host: true` in `group_vars/all/main.yml` (already enabled for Vagrant) to bypass the capacity gate and allocate a 4 GiB swap file.

---

### Step 1: Install Controller Dependencies

On your controller machine, execute the bootstrap script:

```bash
./setup-controller.sh
```

This installs `uv`, creates a hermetic Python virtual environment (`.venv`), and installs Ansible, `passlib`, `cryptography`, and required Ansible Galaxy collections.

---

### Step 2: Configure Settings and Secrets

1. **Configure Inventory**:
   ```bash
   cp inventory/hosts.yml.example inventory/hosts.yml
   ```
   Edit `inventory/hosts.yml` and set `ansible_host` to your target VPS IP. For a fresh target, the initial connection uses `ansible_user: root` (or your cloud image default user).

2. **Configure Settings (`group_vars/all/main.yml`)**:
   - `admin_authorized_keys`: Paste your controller's SSH public key (`cat ~/.ssh/id_ed25519.pub`).
   - `base_domain`: Set your domain (e.g. `example.net`).
   - `traefik_acme_challenge`: Set to `tls` for a public VPS with open port 443, or `dns` for Vagrant/private lab IPs.
   - `cloudflare_dns_enabled`: Set `true` if using Cloudflare to automatically create DNS A-records.

3. **Generate & Encrypt Secrets (`group_vars/all/vault.yml`)**:
   Instead of hand-generating hashes, run the automated vault generator:
   ```bash
   ./generate-vault.sh
   ```
   The script prompts for the `ops` sudo password, a temporary web bootstrap password, and administrative contact emails, then securely generates strong cryptographic keys and bcrypt/yescrypt password hashes for all services. Application credentials are displayed once on stderr—save them to a secure password manager.

   Encrypt the generated vault:
   ```bash
   uv run ansible-vault encrypt group_vars/all/vault.yml
   ```

   *(Optional)* If using Cloudflare DNS automation, edit the vault to add your token:
   ```bash
   uv run ansible-vault edit group_vars/all/vault.yml
   # Add: cloudflare_api_token: "your-cloudflare-api-token"
   ```

---

### Step 3: Run the Playbook

You have two choices for rolling out the platform:

#### Option A: Fast Single-Pass Deployment (Recommended)
If your SSH public key is in `admin_authorized_keys` and your cloud provider's firewall/security group permits inbound ports `22`, `2222`, and `443`, you can deploy the complete stack and lock down the host in a **single run**:

```bash
uv run ansible-playbook site.yml --ask-vault-pass -e firewall_lockdown_confirm=true
```

In one continuous execution, Ansible will:
1. Validate host hardware capacity (CPU, RAM, disk).
2. Create Cloudflare DNS records (if enabled).
3. Apply CIS Debian 13 baseline hardening, create the `ops` administrative user, configure authorized SSH keys, and enforce rootless Podman subordinate UID/GID mappings.
4. Deploy all core platform containers (`edge`, `waf`, `auth`, `forgejo`, `signoz`, `wazuh`).
5. Configure host telemetry (OTel Collector) and packet capture sensors (Suricata, Zeek, SiLK/YAF).
6. Install the host Wazuh agent, Rustinel monitor, and Trivy image scanning timers.
7. Activate strict native `nftables` firewall rules, dropping all unexpected inbound traffic while preserving SSH, Git SSH, and HTTPS.

Once complete, OpenSSH is locked down to key-based authentication for `ops` only. Root SSH login is permanently disabled.

#### Option B: Cautious Two-Step Deployment (Safety Gate)
If you prefer to verify that SSH and web services function correctly before activating the firewall:

**Pass 1 — Full provisioning without firewall lockdown**:
```bash
uv run ansible-playbook site.yml --ask-vault-pass -e firewall_lockdown_confirm=false
```
The firewall rules are generated and syntax-checked, but not activated. Initial source builds and container image pulls take 30–60 minutes.

**Verify connectivity**:
```bash
ssh -p 22 ops@<TARGET_IPV4>
curl -I https://auth.<your-domain>/
```

**Pass 2 — Instant Firewall Lockdown (~3 seconds)**:
Update `inventory/hosts.yml` to use `ops`:
```yaml
ansible_user: ops
ansible_port: 22
ansible_become: true
```
Then activate the firewall:
```bash
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass \
  --tags firewall \
  -e firewall_lockdown_confirm=true
```
> [!TIP]
> **No more waiting for rebuilds**: Using `--tags firewall` targets only the nftables activation tasks. It executes in approximately 3 seconds rather than re-running the entire playbook for 45+ minutes!

---

## Local Vagrant Lab Setup

To test the stack locally using libvirt/KVM:

1. **Launch the VM**:
   ```bash
   ./setup-controller.sh
   vagrant up
   ```
   `vagrant up` boots a Debian 13 image, assigns private networking, and writes `inventory/vagrant.yml`.

2. **Provision with local File CA (`.local` domain)**:
   ```bash
   uv run ansible-playbook site.yml \
     -i inventory/vagrant.yml \
     --ask-vault-pass \
     -e firewall_lockdown_confirm=false
   ```
   In `.local` mode, Traefik uses an internal file CA. The root CA is saved to `tls/lab-ca.pem` on your controller. Test using:
   ```bash
   curl --cacert tls/lab-ca.pem -I https://auth.test.local/
   ```

3. **Subsequent runs on Vagrant**:
   After the initial run, edit `inventory/vagrant.yml` to set `ansible_user: ops` and `ansible_ssh_private_key_file: ~/.ssh/id_ed25519`.

---

## Post-Deployment Application Setup

### 1. Authentik & Admin App Protection

1. Navigate to `https://auth.<base_domain>` and log in as `akadmin` with the password set in `authentik_bootstrap_password`.
2. **Create Users & Groups**: Under **Directory → Groups**, create `external-users`. Under **Directory → Users**, create internal users and assign them to `external-users`.
3. **Protect Admin Dashboards**:
   - In Authentik, create a Proxy Provider and Application for `observe.<base_domain>` (SigNoz), `security.<base_domain>` (Wazuh), and `edge.<base_domain>` (Traefik).
   - Bind these applications to the Embedded Outpost.
   - Once bound, set `protect_admin_apps_with_authentik: true` in `group_vars/all/main.yml` and execute:
     ```bash
     uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags edge,traefik,verify
     ```
   - Traefik will route incoming requests through Authentik forward-auth, replacing temporary Basic Auth with single sign-on.

### 2. Forgejo Git & Optional SSO

- Forgejo runs at `https://git.<base_domain>`.
- Git SSH operates on `ssh://git@git.<base_domain>:2222/owner/repo.git` directly via Forgejo's internal SSH server (independent of host OpenSSH on port 22).
- Initial admin credentials (`forgejo_admin_user` / `forgejo_admin_password`) are configured during deployment.
- Optional Authentik OIDC integration can be configured in Forgejo under **Site Administration → Authentication Sources** by selecting OAuth2/OIDC.

### 3. CI/CD Runner (Forgejo Actions)

1. In the Forgejo web UI, navigate to **Site Administration → Actions → Runners** (or Repository Settings → Actions) and generate a **Registration Token**.
2. Store this token in `group_vars/all/vault.yml` under `forgejo_runner_registration_token` via `uv run ansible-vault edit group_vars/all/vault.yml`.
3. Deploy and register the runner:
   ```bash
   uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags runner
   ```
4. The runner executes within an unprivileged rootless Podman environment using labels `debian-13:docker://node:24-bookworm` and `podman-host:host`.
5. Once registration succeeds, clear `forgejo_runner_registration_token` from your vault.

### 4. Forgejo Packages & Container Workflows

Forgejo Packages serves as an internal OCI container registry listening on `127.0.0.1:13000`. Actions workflows push and pull directly against loopback rather than hairpining through external HTTPS:
- Example workflow available at `examples/forgejo-workflow.yml`.
- Build images using `podman-host` jobs and push to `127.0.0.1:13000/<owner>/<repo>/<image>:<sha>`.
- Trivy automatically scans newly built container images in CI before publication.

### 5. Optional On-Box Application (`scrapecast`)

The platform includes an optional application stack (`svc-scrapecast`) listening on the apex domain (`https://<base_domain>/`):
1. Build and push the application images (`scraper`, `web`, `evasion`) to Forgejo Packages.
2. Generate an access token in Forgejo with `package:read` scope and place it in the vault as `scrapecast_registry_pull_token`.
3. Deploy the application:
   ```bash
   uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags scrapecast,edge
   ```

---

## Available Tags Reference

Playbook tasks and roles are tagged granularly. Use the `--tags` flag to execute specific subsets of the playbook and avoid unnecessary processing.

### Tags Quick Reference Table

| Tag | Affected Roles / Components | Approx. Runtime | Purpose / When to Use |
|---|---|---|---|
| `all` / `setup` | All provisioning roles | 30–60 min | Full platform installation and initial bootstrap. Excludes `backup_restore` and `verify`. |
| `preflight` | `preflight` | 2 sec | Verifies CPU, RAM, disk requirements, and OS compatibility. (Always runs by default). |
| `base` | `base` | 15–30 sec | Host CIS hardening, operator account creation, sudoers, chrony, and rsyslog. |
| `ssh` | `base` (SSH tasks) | 2 sec | Updates OpenSSH daemon configuration, port bindings, and `admin_authorized_keys`. |
| `firewall` | `base` (nftables tasks) | 3 sec | Compiles and syntax-checks nftables rules; activates lockdown if `firewall_lockdown_confirm=true`. |
| `dns` | `dns` | 5 sec | Upserts Cloudflare DNS-only A-records for base domain and subdomains. |
| `platform` | `platform` | 2–5 min | Configures service accounts, directories, and Podman Compose stacks for all admin services. |
| `edge` / `traefik` | `platform` (edge stack) | 10 sec | Configures Traefik reverse proxy, dynamic file providers, TLS certificates, and headers. |
| `waf` | `platform` (waf stack) | 8 sec | Configures CrowdSec v1.8.1 (default) or ModSecurity + CRS reverse proxy containers, AppSec WAF, and Web UI. |
| `auth` / `authentik`| `platform` (auth stack) | 20 sec | Deploys Authentik server, worker, and PostgreSQL database. |
| `forgejo` | `platform` (forgejo stack)| 15 sec | Deploys Forgejo Git server, configuration, and SQLite storage. |
| `signoz` | `platform` (signoz stack) | 30 sec | Deploys SigNoz observability stack, ClickHouse, Keeper, and query engine. |
| `wazuh` / `wazuh_server`| `platform` (wazuh stack) | 30 sec | Deploys Wazuh manager, indexer, and dashboard containers. |
| `fail2ban` | `fail2ban` | 5 sec | Configures fail2ban jail definitions and nftables/WAF banning integration. |
| `telemetry` | `telemetry` | 15 sec | Configures host OpenTelemetry Collector, journald log collection, and metrics export. |
| `otelcol` | `telemetry` (collector) | 5 sec | Updates `/etc/otelcol-contrib/config.yaml` and restarts the host collector. |
| `alerts` / `signoz_alerts` | `telemetry` (alert rules) | 4 sec | Upserts managed operational alerting rules into SigNoz via the SigNoz API. |
| `sensors` | `sensors` | 10–25 min | Compiles and configures Suricata IDS, Zeek NSM, and YAF/SiLK flow capture. |
| `suricata` | `sensors` (Suricata only) | 5 sec | Updates Suricata configuration and rules without recompiling Zeek or SiLK. |
| `zeek` | `sensors` (Zeek only) | 10–15 min | Compiles from source and configures Zeek network security monitor. |
| `silk` / `yaf` | `sensors` (SiLK & YAF) | 5–10 min | Compiles and configures YAF flow sensor and SiLK flow capture storage. |
| `rustinel` | `rustinel` | 5 sec | Deploys Rustinel process and network monitoring binary and ruleset. |
| `trivy` | `trivy` | 15 sec | Installs Trivy binary and configures scheduled per-service container image scan timers. |
| `wazuh_agent` | `wazuh_agent` | 20 sec | Installs host Wazuh agent, syncs Sigma detection rules, and connects to manager. |
| `runner` | `runner` | 15 sec | Configures Forgejo Actions runner service and rootless Podman execution environment. |
| `scrapecast` | `scrapecast` | 15 sec | Deploys scrapecast on-box application containers and database. |
| `backup` | `backup` | 10 sec | Configures resticprofile off-site backup hooks and systemd timers. |
| `restore` | `backup_restore` | 1–5 min | Extracts offsite restic backup snapshots to staging directory. (Requires `backup_restore_confirm=true`). |
| `verify` | `verify` | 30 sec | Executes end-to-end integration tests, HTTP endpoint probes, and Wazuh detection fixtures. |

---

### Practical Tag Recipes

Save time during development and maintenance by running only the necessary tasks:

```bash
# Update firewall rules without touching any containers (~3 seconds)
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags firewall -e firewall_lockdown_confirm=true

# Refresh Suricata IDS rules without recompiling Zeek or SiLK (~5 seconds)
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags suricata

# Reload Traefik routing or WAF configuration (~10 seconds)
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags edge,waf

# Push updated SigNoz alert rules as code (~4 seconds)
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags alerts

# Sync Wazuh agent Sigma detection rules and test logtest fixtures (~20 seconds)
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags wazuh_agent

# Rotate Wazuh root CA and node certificates
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags platform -e wazuh_rotate_certificates=true

# Trigger manual offsite backup staging and snapshot
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags backup

# Run end-to-end verification and service health checks
uv run ansible-playbook site.yml --ask-vault-pass --ask-become-pass --tags verify
```

---

## Available Variables Reference

### 1. Identity, Access & System Exposure (`group_vars/all/main.yml`)

| Variable | Default | Purpose / When to Modify |
|---|---|---|
| `platform_hostname` | `secure-vps` | Hostname configured on the target Linux instance. |
| `admin_user` | `ops` | Name of the primary unprivileged administrative user created by the `base` role. |
| `admin_authorized_keys` | `[]` | List of SSH public keys granted access to `admin_user`. Required before deployment. |
| `admin_uid` | `2000` | Numerical UID assigned to `admin_user`. |
| `ssh_port` | `22` | Host OpenSSH listening port. |
| `public_port` | `443` | Public HTTPS port bound by Traefik. |
| `forgejo_ssh_port` | `2222` | Public Git SSH port bound by the Forgejo container. |
| `fail2ban_ignoreip` | `[]` | CIDR list of trusted IPs that fail2ban will never ban (e.g. office or VPN IPs). |
| `fail2ban_bantime` | `1h` | Initial ban duration for repeated authentication failures. |
| `fail2ban_findtime` | `10m` | Time window within which authentication failures are counted. |
| `fail2ban_sshd_maxretry` | `5` | Maximum failed SSH attempts before IP is banned. |
| `fail2ban_forgejo_maxretry` | `10` | Maximum failed Forgejo login attempts before IP is banned. |

### 2. Safety & Hardening Confirmation Gates

These safety gates prevent accidental lockout during automated deployments:

| Variable | Default | Safety Gate Description |
|---|---|---|
| `firewall_lockdown_confirm` | `false` | When `false`, candidate nftables rules are compiled and syntax-checked, but the active firewall is unchanged. Set `true` only when SSH (port 22) and HTTPS (port 443) reachability are proven. |
| `pam_hardening_confirm` | `false` | When `true`, enforces strict password quality checks (`pwquality`), password history, and `use_authtok`. Enable only during maintenance windows with console access. |
| `root_account_lock_confirm` | `false` | When `true`, locks the local Linux root account password. Enable only after operator sudo access is thoroughly verified. |
| `backup_restore_confirm` | `false` | When `true`, enables extraction of offsite restic backup snapshots into `/var/lib/platform-backup/restore`. |

### 3. Domain, DNS & ACME TLS Certificates

| Variable | Default | Purpose / When to Modify |
|---|---|---|
| `base_domain` | `aimingupward.com` | Primary root domain for the deployment. |
| `auth_fqdn` | `auth.{{ base_domain }}` | FQDN for the Authentik identity provider. |
| `git_fqdn` | `git.{{ base_domain }}` | FQDN for Forgejo Git and Packages. |
| `observe_fqdn` | `observe.{{ base_domain }}` | FQDN for the SigNoz observability dashboard. |
| `security_fqdn` | `security.{{ base_domain }}` | FQDN for the Wazuh SIEM/XDR dashboard. |
| `crowdsec_fqdn` | `waf.{{ base_domain }}` | FQDN for the CrowdSec Web UI (protected by Authentik forward-auth). |
| `traefik_fqdn` | `edge.{{ base_domain }}` | FQDN for the Traefik management dashboard. |
| `app_fqdn` | `{{ base_domain }}` | Apex domain routed to the optional on-box app (`scrapecast`). |
| `app_www_fqdn` | `www.{{ base_domain }}` | WWW domain redirected to `app_fqdn`. |
| `waf_provider` | `crowdsec` | WAF engine selection: `crowdsec` (default, with decision-stream bouncer and Web UI) or `modsecurity` (fallback reverse proxy). |
| `crowdsec_appsec_enabled` | `false` | Enables inline CrowdSec AppSec inspection in Traefik. Leave disabled until a live canary confirms no false positives. |
| `crowdsec_enroll_key` | `""` | Optional enrollment key to connect instance to CrowdSec Console (`https://app.crowdsec.net`). |
| `cloudflare_dns_enabled` | `false` | When `true`, the `dns` role creates DNS-only A-records in Cloudflare using the vault token. |
| `cloudflare_zone` | `{{ base_domain }}` | Cloudflare DNS zone name. Change if `base_domain` is a subdomain within a larger zone. |
| `cloudflare_record_ipv4` | `""` | IP address to publish in DNS. If empty, uses `ansible_default_ipv4.address`. |
| `traefik_acme_enabled` | `{{ not base_domain.endswith('.local') }}` | Enables automatic Let's Encrypt certificate issuance via ACME. |
| `traefik_acme_challenge` | `tls` | ACME challenge type: `tls` (TLS-ALPN-01 on TCP 443 for public VPS) or `dns` (DNS-01 via Cloudflare for private labs). |
| `traefik_acme_ca_server` | *(commented)* | Uncomment to use Let's Encrypt Staging directory (`https://acme-staging-v02.api.letsencrypt.org/directory`) to avoid rate limits. |
| `protect_admin_apps_with_authentik` | `true` | When `true`, Traefik enforces Authentik forward-auth SSO in front of SigNoz, Wazuh, CrowdSec Web UI, and Traefik dashboard. |

### 4. Hardware Sizing & Resource Tuning

| Variable | Default | Purpose / When to Modify |
|---|---|---|
| `minimum_vcpus` | `8` | Minimum vCPU count enforced by `preflight` role. |
| `minimum_memory_mb` | `20000` | Minimum RAM in megabytes (~20 GiB) enforced by `preflight`. |
| `minimum_root_disk_gb` | `200` | Minimum disk space in gigabytes on root filesystem. |
| `allow_undersized_host` | `true` | When `true`, allows deployment to proceed on smaller hosts (such as local Vagrant VMs). |
| `undersized_swap_mb` | `4096` | Size of the swapfile created on undersized hosts to prevent ClickHouse OOM errors. |
| `source_build_jobs` | `2` | Number of parallel build processes used when compiling Zeek, YAF, and SiLK from source. |
| `suricata_af_packet_threads` | `1` | AF_PACKET worker threads per network capture interface. |
| `suricata_detect_thread_ratio` | `0.5` | Ratio of CPU cores allocated to Suricata signature pattern matching. |

### 5. Component Feature Toggles & Lifecycle Flags

| Variable | Default | Purpose / When to Modify |
|---|---|---|
| `enable_suricata` | `true` | Deploys Suricata network threat detection engine. |
| `enable_zeek` | `true` | Compiles and deploys Zeek network security monitor. |
| `enable_silk` | `true` | Compiles and deploys YAF IPFIX flow probe and SiLK flow capture. |
| `rustinel_enabled` | `true` | Deploys Rustinel host process and network telemetry monitor. |
| `enable_scrapecast` | `true` | Configures the optional `scrapecast` product application stack. |
| `backup_offsite_enabled` | `false` | Enables scheduled off-site restic backups to Backblaze B2 over S3 API. |
| `wazuh_rotate_certificates` | `false` | When `true`, forces rotation of the Wazuh root CA and all node certificates. |
| `signoz_reset_telemetrystore` | `false` | When `true`, resets ClickHouse and Keeper storage volumes to repair schema mismatches. |
| `wazuh_reset_store` | `false` | When `true`, wipes Wazuh indexer/manager data volumes to recover from initialization failure. |
| `trivy_verify_scan_results` | `false` | When `true`, `--tags verify` requires completed Trivy vulnerability scan reports for each service account. |

### 6. Service Loopback Ports & Networks

All internal services bind strictly to loopback (`127.0.0.1`):

| Variable | Port | Service Component |
|---|---|---|
| `authentik_http_port` | `19000` | Authentik web server and embedded outpost |
| `authentik_metrics_port` | `19300` | Authentik Prometheus metrics endpoint |
| `forgejo_http_port` | `13000` | Forgejo Git web interface and OCI Packages registry |
| `signoz_ui_port` | `18080` | SigNoz web frontend |
| `signoz_grpc_port` | `14317` | SigNoz query service gRPC |
| `signoz_http_port` | `14318` | SigNoz query service HTTP |
| `wazuh_dashboard_port` | `15601` | Wazuh Kibana/OpenSearch web dashboard |
| `wazuh_indexer_port` | `19200` | Wazuh OpenSearch indexer REST API |
| `crowdsec_lapi_port` | `18085` | CrowdSec Local API (LAPI) engine |
| `crowdsec_appsec_port` | `17422` | CrowdSec AppSec WAF acquisition endpoint |
| `crowdsec_metrics_port` | `18086` | CrowdSec Prometheus metrics endpoint |
| `crowdsec_web_ui_port` | `18092` | CrowdSec Web UI management dashboard |
| `waf_http_port` | `18090` | ModSecurity OWASP Core Rule Set reverse proxy (when `waf_provider: modsecurity`) |
| `waf_status_port` | `18091` | ModSecurity Nginx stub_status metrics (when `waf_provider: modsecurity`) |
| `host_otlp_grpc_port` | `4317` | Host OpenTelemetry Collector gRPC receiver |
| `host_otlp_http_port` | `4318` | Host OpenTelemetry Collector HTTP receiver |
| `scrapecast_web_port` | `43147` | Scrapecast web frontend |
| `scrapecast_api_port` | `43148` | Scrapecast API backend |

---

### 7. Encrypted Secrets Catalog (`group_vars/all/vault.yml`)

These secrets are generated automatically by `./generate-vault.sh` and stored in `vault.yml`:

| Secret Variable | Purpose / Description |
|---|---|
| `admin_password_hash` | Cryptographic password hash (yescrypt or SHA-512) for the `ops` user's sudo access. |
| `acme_email` | Administrative email address provided to Let's Encrypt for TLS expiry warnings. |
| `bootstrap_admin_htpasswd` | Bcrypt htpasswd line used for temporary Basic Auth on admin endpoints prior to Authentik binding. |
| `authentik_postgresql_password` | Database password for Authentik's dedicated PostgreSQL instance. |
| `authentik_secret_key` | Secret encryption key used by Authentik for session signing and credential encryption. |
| `authentik_bootstrap_password` | Initial login password for the default `akadmin` administrative account. |
| `authentik_bootstrap_token` | Bootstrap API token used by Ansible to provision initial Authentik providers. |
| `authentik_bootstrap_email` | Administrative email associated with the `akadmin` user. |
| `forgejo_secret_key` | Secret key used by Forgejo for session token signing. |
| `forgejo_internal_token` | Internal communication token between Forgejo web and worker processes. |
| `forgejo_admin_user` | Username of the initial Forgejo administrator account. |
| `forgejo_admin_password` | Password of the initial Forgejo administrator account. |
| `forgejo_admin_email` | Email of the initial Forgejo administrator account. |
| `signoz_postgresql_password` | Database password for SigNoz metadata PostgreSQL instance. |
| `signoz_api_token` | *(Optional)* SigNoz API key for automated alerting rule management. |
| `wazuh_indexer_admin_password` | Plaintext administrator password for the Wazuh OpenSearch indexer. |
| `wazuh_indexer_admin_hash` | Bcrypt hash of `wazuh_indexer_admin_password` mounted into the indexer security config. |
| `wazuh_dashboard_service_password`| Password used by the Wazuh dashboard to communicate with the indexer. |
| `wazuh_dashboard_service_hash` | Bcrypt hash of `wazuh_dashboard_service_password`. |
| `wazuh_api_password` | Password for the Wazuh manager REST API (`wazuh-wui`). |
| `vault_crowdsec_bouncer_api_key` | API key used by Traefik CrowdSec bouncer plugin to communicate with CrowdSec LAPI. |
| `vault_crowdsec_web_ui_api_key` | API credentials for the self-hosted CrowdSec Web UI container to authenticate with LAPI. |
| `cloudflare_api_token` | *(Optional)* Cloudflare API token with `Zone.DNS Edit` and `Zone.Zone Read` permissions. |
| `backup_b2_key_id` | *(Optional)* Backblaze B2 Application Key ID for off-site backups. |
| `backup_b2_application_key` | *(Optional)* Backblaze B2 Application Key secret. |
| `backup_restic_password` | *(Optional)* Encryption password used by restic for offsite backup repository encryption. |

---

## Day-to-Day Operations & Maintenance

### Diagnostic Commands on the Target Host

Execute these commands directly on the target VPS as the `ops` user:

```bash
# Check for any failed systemd units across the entire host
systemctl --failed

# Check status of platform container stacks
systemctl status secure-edge secure-waf secure-auth secure-forgejo secure-signoz secure-wazuh secure-scrapecast

# View recent logs for the Traefik reverse proxy
journalctl -u secure-edge --since today -f

# Inspect rootless containers running under a specific service account
sudo -u svc-forgejo env HOME=/var/lib/svc-forgejo XDG_RUNTIME_DIR=/run/user/2103 podman ps

# Check status of network packet sensors
systemctl status suricata-platform 'zeek@*' 'yaf-*' silk-rwflowpack

# Inspect listening TCP and UDP sockets (verify only 22, 2222, and 443 are public)
ss -lntup

# Inspect active nftables firewall filtering table
sudo nft list table inet ansible_filter
```

---

## Architecture and Security Deep Dive

### Security Isolation Boundaries

| Boundary | Components | Public Exposure | Description |
|---|---|---|---|
| **Host System** | nftables, OpenSSH, OTel Collector, Wazuh Agent, Rustinel | `22/tcp`, `2222/tcp`, `443/tcp` | Native Debian 13 host processes hardened according to CIS benchmarks. |
| `svc-edge` | Traefik v3, ACME client, security middleware | `0.0.0.0:443` | Rootless account. Terminates public TLS; routes to localhost backends. |
| `svc-waf` | CrowdSec v1.8.1 (AppSec Coraza WAF + Web UI) or ModSecurity v3 + CRS | `127.0.0.1:18085`, `17422`, `18092` (CrowdSec) / `18090` (ModSecurity) | Rootless account. Inspects incoming HTTP requests for malicious payloads and manages threat intelligence decisions. |
| `svc-auth` | Authentik server, worker, PostgreSQL | `127.0.0.1:19000` | Rootless account. Identity provider, SSO, and forward-auth gateway. |
| `svc-forgejo` | Forgejo Git, SQLite database | `127.0.0.1:13000` (HTTP), `0.0.0.0:2222` (SSH) | Rootless account. Self-hosted Git repositories and OCI package registry. |
| `svc-signoz` | SigNoz, ClickHouse, Keeper, OTel collector | `127.0.0.1:18080`, `14317` | Rootless account. Application metrics, distributed traces, and operations logs. |
| `svc-wazuh` | Wazuh manager, indexer, dashboard | `127.0.0.1:15601`, `19200` | Rootless account. Central SIEM, FIM, security detections, and agent manager. |
| `svc-runner` | Forgejo Actions runner + rootless Podman | No listening ports | Rootless account. Executes CI workflows inside disposable Podman containers. |
| `svc-scrapecast` | On-box product application stack | `127.0.0.1:43147`, `43148` | Rootless account. Isolated product web and API services. |
| **Sensor Users** | Suricata, Zeek, YAF, SiLK | Passive packet capture | Dedicated unprivileged system accounts without shell or login permissions. |

Each rootless service account is locked (`/usr/sbin/nologin`), has no sudo privileges, possesses a private `0700` home directory, and operates within a non-overlapping subordinate UID/GID range (`subuid`/`subgid`).

---

### CIS Debian 13 Hardening

The `base` role implements baseline controls oriented around the CIS Debian 13 benchmark:
- **Authentication & SSH**: Disables SSH password authentication, root login, X11 forwarding, and agent forwarding; enforces strong cryptographic MACs and ciphers; requires password-authenticated sudo for `ops`.
- **System Integrity**: Configures `auditd` kernel auditing, deterministic Podman journal logging, `rsyslog` logging, and file integrity monitoring (FIM) paths for host configuration.
- **Firewall Policy**: Implements default-deny inbound and forward filtering in native `nftables`. Outbound traffic is permitted for DNS, NTP, ACME, image pulls, and security updates.
- **Fail2ban Integration**: Watches OpenSSH and Forgejo authentication failures; dynamically adds offending IPs to the `inet f2b-table` nftables set and WAF blocklist.

---

### Why TLS-ALPN Needs a Public IP

`traefik_acme_challenge: tls` uses Let's Encrypt TLS-ALPN-01 validation. Let's Encrypt looks up your hostname in public DNS, connects to that IP on TCP/443, and completes a specialized TLS handshake using the `acme-tls/1` protocol. Traefik serves a short-lived certificate to prove ownership.

Because Let's Encrypt must connect directly to TCP/443, TLS-ALPN cannot work behind NAT or on private IPs (e.g. local Vagrant VMs). For private environments, set `traefik_acme_challenge: dns` and provide Cloudflare API credentials. Traefik will then create an `_acme-challenge` DNS TXT record without requiring inbound connectivity.

---

### Telemetry Architecture

| Signal | Source | Destination |
|---|---|---|
| **Metrics** | Host CPU/RAM/disk, WAF stub_status, Podman container stats, Traefik metrics | Host OTel Collector → SigNoz ClickHouse |
| **Traces** | Traefik distributed traces, application OTLP traces | Host OTel Collector (`127.0.0.1:4317`) → SigNoz |
| **Application Logs** | Traefik access logs, systemd operations logs (`signoz_operations_journal_units`) | Host OTel Collector (`127.0.0.1:4318`) → SigNoz |
| **Security Events** | Auditd, auth logs, SSH, sudo, fail2ban, WAF detections, Suricata alerts, Zeek notices | Host Wazuh Agent → Wazuh Manager / Indexer |

Security detections are strictly separated from operational metrics. Wazuh handles security events and Sigma detection rules, while SigNoz handles performance metrics and traces.

---

### Packet Visibility & Wazuh SIEM

- **Suricata**: Captures traffic on external WAN interface and `lo` using `AF_PACKET`. Generates `eve-security.json` alert/anomaly records ingested by Wazuh.
- **Zeek**: Passive protocol analyzer that generates structured connection, notice, and protocol logs.
- **YAF & SiLK**: Generates IPFIX flow records stored under `/var/lib/silk/data` for historical network forensics.
- **Wazuh 5.x Integration**: Utilizes modern Sigma rules (`roles/wazuh_agent/files/engine/rules.json`) published via the Wazuh Content Manager. Pre-flight verification validates detection logic using the Wazuh logtest API before promotion to production.

---

### Backups and Recovery

Off-site backups use `resticprofile` and `restic` targeting Backblaze B2 (or any S3-compatible object storage):
1. **Enable Backups**: Set `backup_offsite_enabled: true` in `main.yml` and provide `backup_b2_*` credentials in `vault.yml`.
2. **Scheduled Execution**: Systemd timers trigger automated staging dumps at `02:30:00` daily. Staging includes PostgreSQL databases (`authentik`, `signoz`, `scrapecast`), ClickHouse database dumps, Forgejo repositories/LFS/packages, Wazuh indexer snapshots, and Traefik `acme.json`.
3. **Disaster Recovery**: To restore data, run the playbook with the `restore` tag:
   ```bash
   uv run ansible-playbook site.yml --tags restore --ask-vault-pass --ask-become-pass -e backup_restore_confirm=true
   ```
   Restic restores snapshots to `/var/lib/platform-backup/restore/` for manual inspection and volume re-population. Live volumes are never automatically overwritten.

---

## Primary References

- [Debian 13 Podman Documentation](https://packages.debian.org/trixie/podman) and [OpenSSH](https://packages.debian.org/trixie/openssh-server)
- [Traefik v3 Documentation](https://doc.traefik.io/traefik/)
- [CrowdSec Security Engine & AppSec WAF](https://docs.crowdsec.net/)
- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/)
- [Authentik Documentation](https://docs.goauthentik.io/)
- [Forgejo Administrator Guide](https://forgejo.org/docs/latest/admin/)
- [SigNoz Documentation](https://signoz.io/docs/)
- [Wazuh 5.x SIEM & XDR Guide](https://documentation.wazuh.com/)
- [Suricata Documentation](https://docs.suricata.io/)
- [Zeek Network Security Monitor](https://docs.zeek.org/)
- [CERT NetSA SiLK Flow Tools](https://tools.netsa.cert.org/silk/)
