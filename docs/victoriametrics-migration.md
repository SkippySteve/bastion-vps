# Replace Wazuh and SigNoz with Victoria observability

  ## Summary

  Make victoria the default security_observability_stack for new deployments. It runs rootless VictoriaMetrics, VictoriaLogs, Tempo, Grafana, vmagent, vmalert,
  and Alertmanager. It replaces Wazuh with Vector log collection, Falco eBPF runtime detection, AIDE integrity checks, and scheduled OpenSCAP scans.

  Keep the current Wazuh plus SigNoz deployment as the legacy_wazuh_signoz profile. It remains supported but disabled by default. Require an explicit purge flag
  and confirmation value before stopping legacy units and deleting their volumes.

  ## Key changes

  - Add svc-victoria and conditional rootless stack definitions. Bind component ports to loopback only; expose Grafana through observe_fqdn, protected by the
    existing admin chain. Redirect security_fqdn to Grafana's security dashboard.

  - Add pinned image/version/checksum variables, storage paths, and defaults:
      - VictoriaMetrics: 90-day retention.
      - VictoriaLogs: 30-day retention with an 80% volume-use guardrail.
      - Tempo: 14-day retention.
      - All signal storage lives on dedicated named volumes and joins the existing backup flow.

  - Replace the host metrics pipeline with node_exporter -> vmagent -> VictoriaMetrics; vmagent also scrapes Forgejo, Authentik, and CrowdSec. The host
    OpenTelemetry Collector forwards host, Traefik, and application OTLP metrics to VictoriaMetrics by Prometheus remote write.

  - Keep the per-account Podman stats collectors, forwarding their metrics to VictoriaMetrics by Prometheus remote write. Send application OTLP traces to
    Tempo and application OTLP logs to VictoriaLogs.

  - Add a root-managed Vector service with durable checkpoints. Collect journald, auditd, auth, sudo, fail2ban, package, Trivy, Rustinel, Suricata, Zeek, and
    container logs; parse JSON, syslog, and audit records; retain source fields; send structured events to VictoriaLogs.

  - Add Falco with the eBPF probe and Falcosidekick. Install a constrained local ruleset for interactive container shells, privilege escalation, sensitive host
    paths, unexpected package or service changes, and suspicious shell execution. Send Falco alerts to VictoriaLogs and Alertmanager.

  - Add AIDE baseline initialization plus a daily systemd timer. Store reports as structured VictoriaLogs events and alert on baseline changes or failed checks.
  - Add a periodic OpenSCAP Debian CIS scan. Emit JSON or JUnit-derived structured results to VictoriaLogs and publish a compliance score metric to
    VictoriaMetrics. Alert on scan failure and score regression.

  - Replace the Wazuh Content Manager publisher with a checked-in detection catalog:
      - Preserve the existing detection IDs and coverage for authentication abuse, auditd, WAF and Traefik events, Suricata, Zeek, Trivy, and Rustinel.
      - Map kernel and runtime detections to Falco rules.
      - Maintain Sigma source metadata alongside validated compiled LogsQL vmalert rules for log detections. Use a bounded translation script or manifest for
        this catalog, rather than claiming arbitrary Sigma YAML can run directly.

      - Configure LogsQL rule groups with type: vlogs, a stats pipeline, stable labels, and representative-event annotations.

  - Replace SigNoz alerts with vmalert metric and LogsQL rules, backed by Alertmanager. Cover disk, CPU, memory, OOM and unit failures, scrape and ingest
    failures, log timestamp drops, SSH brute force, app 5xx/auth failures, Trivy critical findings, Falco alerts, AIDE changes, and OpenSCAP regressions.

  - Provision Grafana datasources for VictoriaMetrics, VictoriaLogs, and Tempo plus an overview and security dashboard. Route SMTP when its vault configuration
    is complete; independently enable a generic webhook when configured. Keep the new vault values empty by default.

  - Update backup, restore, verification, render tests, and README content so they select behavior from the active profile. Legacy backups keep their current
    Wazuh and SigNoz exports. Victoria backups include the three data volumes, Grafana state, alert rules, and provisioning files.

  ## Public configuration

  - security_observability_stack: victoria accepts victoria or legacy_wazuh_signoz.
  - Add retention, storage-cap, image-pin, port, SMTP, webhook, Falco, AIDE, and OpenSCAP schedule variables with the defaults above.
  - Add legacy_telemetry_purge: false and legacy_telemetry_purge_confirm: "". Purging requires the Victoria profile, legacy_telemetry_purge: true, and the exact
    confirmation string DELETE-WAZUH-SIGNOZ; it stops/disables legacy services before removing their Wazuh and SigNoz volumes and credentials.

  - Remove trace settings only from the legacy SigNoz path. Preserve Traefik and application OTLP tracing for Tempo.

  ## Test plan

  - Render both profiles and validate Compose, systemd, Vector, vmagent, vmalert, Alertmanager, Falco, AIDE, OpenSCAP, Grafana provisioning, and Traefik redirect
    configuration.

  - Add unit tests for Vector event normalization and detection-catalog translation, including every current Wazuh fixture and rule ID.
  - Add profile-aware verification checks for active units, loopback listeners, Grafana routes, datasource health, ingestion of representative metric/log/trace
    events, alert delivery configuration, Falco test events, AIDE baseline changes, and OpenSCAP score emission.

  - Confirm legacy services and data remain untouched unless both purge controls are supplied; confirm the purge path refuses an invalid profile or confirmation.
  - Run the existing Ansible render suite, Python tests, and a Victoria-profile smoke deployment before switching the default in documentation.

  ## Assumptions

  - This remains a single-node deployment. No historical SigNoz or Wazuh data is imported or retained after an authorized purge.
  - Vector is the log collector; vmagent is the metrics collector. Tempo is included because traces must remain available.
  - vmalert evaluates LogsQL against VictoriaLogs and sends notifications through Alertmanager, as supported by the VictoriaLogs integration. VictoriaLogs
    vmalert docs

  - Retention defaults follow the selected operating profile, with VictoriaMetrics and VictoriaLogs configured explicitly because their defaults differ.
    VictoriaMetrics retention, VictoriaLogs retention
