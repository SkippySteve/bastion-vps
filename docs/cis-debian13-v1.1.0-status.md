# CIS Debian Linux 13 v1.1.0 remediation status

This status applies to the findings supplied for host `secure-vps`. The design
priority is recoverability and service availability. Security events introduced
or exposed by these controls are collected by the native Wazuh agent.

## Applied by default

- 33048, 33049, 33050: `/etc/motd`, `/etc/issue`, and `/etc/issue.net` use a
  generic legal warning with root ownership and mode `0644`.
- 33097, 33098: chrony and cron are installed, enabled, and started.
- 33099 through 33104: `/etc/crontab` is `0600`; cron directories are `0700`.
- 33137, 33138: the selected nftables policy defines input, forward, and output
  base chains and explicitly accepts loopback. Activation remains gated.
- 33158, 33161, 33168, 33171: OpenSSH configures the banner,
  `DisableForwarding`, EtM SHA-2 MACs, and `MaxStartups 10:30:60`; `sshd -t` runs
  before the restart and the verify role checks the effective configuration. The
  managed drop-in loads first so provider drop-ins cannot silently win.
- 33178, 33181, 33182: sudo writes a protected log, caches authentication
  for no more than 15 minutes, and `su` is restricted to `sugroup` (root retains
  its standard PAM bypass and the operator is enrolled).
- 33185: `libpam-pwquality` is installed.
- 33208, 33209, 33210: new-account defaults and the managed operator use maximum,
  minimum, warning, and inactive-account aging values.
- 33211: new passwords default to YESCRYPT. Existing vault hashes are not
  silently rotated because Ansible does not know their plaintext.
- 33217: root SSH access is disabled. Local password locking is separately gated.
- 33229: `systemd-journal-remote` is installed.
- 33236: rsyslog is installed, enabled, and started; its auth and system logs are
  ingested by Wazuh.

## Applied only after explicit confirmation

- 33140: `firewall_lockdown_confirm=true` installs and enables the validated
  nftables policy. Input and forward default to drop. Output remains allowed to
  avoid breaking DNS, NTP, ACME, OIDC, updates, image pulls, and telemetry.
- 33188, 33189, 33201, 33202, 33203, 33204, 33207:
  `pam_hardening_confirm=true` extends the recognized Debian password stack with
  pwquality and pwhistory, enforces history for root, uses `use_authtok`, and
  removes `nullok`. Do this only with provider-console access.
- 33217: `root_account_lock_confirm=true` additionally locks the local root
  password after operator sudo and console recovery have been tested.

## Intentionally not applied

- 33126, 33128: UFW is not installed or enabled because nftables is selected.
- 33143, 33144, 33146, 33147, 33150, 33151: legacy iptables/ip6tables controls
  are not installed alongside the selected nftables implementation.
- 33140: the output chain is not default-deny. This is the documented
  availability-over-egress-restriction tradeoff.
- 33179: the managed operator rule is password-required and loaded late, but the
  playbook does not delete unknown provider `NOPASSWD` rules that may belong to
  a recovery account.
- 33187: faillock policy is staged in `/etc/security/faillock.conf`, but generic
  insertion of pre-auth, failure, success, and account entries into a customized
  provider PAM stack is not automated. An incorrect order can remove sudo and
  console access.
- 33231: `systemd-journal-upload` is explicitly stopped and disabled. No remote
  journal endpoint was provided, and Wazuh is the required centralized event
  sink. Enabling an unconfigured duplicate uploader would fail continuously.

## Wazuh coverage

Wazuh ingests the audit log, sudo log, rsyslog auth/system logs, cron/chrony and
security-service journals, nftables drop events, package logs, selected container
security events, IDS metadata, WAF events, and Trivy findings. File-integrity
monitoring covers the banner, cron, SSH, sudo, PAM, login, firewall, and related
policy paths. Audit watches cover changes to the newly managed banner, cron, and
authentication policy files.
