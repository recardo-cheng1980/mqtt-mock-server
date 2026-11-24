# Credential compliance and access monitoring

Status: proposed; implementation and DUT verification are pending.

## Purpose and scope

Continuously monitor password authentication and certificate and private-key
configuration and use across the Host, DMZ, IT and OT planes, regardless of
whether credentials are defaults. Separately detect known factory defaults.
Support TPM-backed keys accessed through approved signing brokers and
file-based keys. Emit actionable evidence to the existing Host logging and
SIEM path without exposing passwords, hashes, private keys or signing payloads.

## Architecture

```text
Host and zone credential inventory ──> periodic compliance checks ──┐
Host kernel audit: file access ──────> audit event correlation ─────┤
Host TPM signing brokers ────────────> signing access events ───────┤
Password, TLS/SSH service logs ──────> authentication events ──────┤
                                                                   v
                                               Host journal / local retention
                                                                   |
                                               Host rsyslog -> TLS -> SIEM
```

The Host owns the policy and monitoring service. Existing zone roots and
namespaces are inspected through explicitly controlled Host interfaces; do not
add an rsyslog or Vault Agent to each zone. Host rsyslog currently handles Host
logs only. A separate, bounded and authenticated zone-event collection mechanism
must be designed and verified before claiming zone journal coverage.

The Host performs every inventory, check and event collection that it can obtain
reliably through an approved Host interface, including zone information. A zone
checker or adapter is justified only for a specific datum that cannot be obtained
reliably from the Host and is available inside that zone; document the evidence
and narrow interface before adding one. A zone may need no checker. If neither
side can obtain a datum, report unknown rather than inventing an adapter.

The configured LXC rootfs paths are Host-managed, and the DUT exposed all three
merged `/etc/shadow` paths to Host root during inspection. This establishes path
visibility, not correct live-mount resolution, permission under SELinux enforcing,
or safe and accurate access during zone lifecycle changes. Verify those properties
before choosing the Host-side implementation; do not duplicate a shadow checker
in a zone merely because the account belongs there.

### Responsibility and collection matrix

| Information or task | Responsible component | Validation or limitation |
| --- | --- | --- |
| Zone services, accounts, configured authentication paths and credential inventory | Host | Resolve names and configuration in the correct zone context; verify live mounts, namespace identity and lifecycle. |
| Local password default comparison and account/login state | Host | Use narrowly scoped access to the appropriate authority; visibility of a shadow path alone is insufficient to establish a safe live read or an enabled login path. |
| Certificate and file-key configuration, metadata and known-default public identities | Host | Resolve the running consumer's actual configuration and mounts; do not export private key material. |
| File-key access events | Host Linux Audit collector | Verify namespace attribution, denial visibility, rotation, event loss and rules on the DUT. |
| TPM signing and public identity | Host broker or other verified Host-side source | Verify request attribution and outcome; identify direct TPM clients and report unsupported coverage. |
| Password, SSH and TLS authentication outcomes | Host collector | Collect from authoritative sources accessible to Host; Host journal alone does not provide zone journal coverage. Verify method, outcome and loss handling. |
| Scheduling, policy, correlation, health and SIEM forwarding | Host | Check freshness, queue capacity, delivery and recovery; report gaps rather than inferring success. |
| A specific datum unavailable through any reliable approved Host interface | Zone-owned adapter, only if proven necessary | Demonstrate the Host limitation and zone capability first; expose only the minimum non-secret result. If unavailable in both places, report unknown. |

No mandatory zone checker has been identified. A zone-owned adapter is not a
fallback for an untested Host collection path, and a missing zone adapter is not
itself a finding when the Host can collect the evidence. Record the selected
source, coverage and rationale per service before implementation. Service-owned
instrumentation for an otherwise unavailable authentication outcome remains
owned by that service and is not automatically a separate zone checker.

## Policy and inventory

A versioned, root-controlled policy maps each plane and service to its expected
account, certificate purpose, allowed issuer or trust anchor, certificate
location, key storage type, approved broker or file path, expected callers,
expiration thresholds and password-login state. Identify roles and accounts by
names resolved through the appropriate plane's NSS, not fixed numeric IDs.
Provide explicit defaults in configuration and fail visibly if a required
policy entry or source cannot be evaluated. Record policy version in events.

The inventory includes all six managed local roles and the commissioned MQTT,
LDAP, syslog and SSH identities. Discover and verify the complete set of actual
certificate consumers and trust stores on the DUT before enabling enforcement.
Configured file paths may be symlinks or regenerated on renewal; identity must
be tied to a validated target and updated atomically with commissioning and
rotation. Treat bootstrap and commissioned TPM identities as distinct phases.

## Compliance checks

Run at boot, on a bounded periodic schedule, and after relevant password,
commissioning, renewal, reset or configuration changes. Persist the last
successful scan and raise a monitoring-health event on failure or stale data.

* **Passwords:** for each managed account in each plane, test the shipped
  default against its current shadow hash using the hash's own algorithm and
  salt; also report first-login expiry and whether password authentication is
  enabled. Keep password-present and login-enabled as separate findings. Never
  transmit or log password candidates, hashes or shadow records. Do not reset
  credentials or change expiry. Detection covers known shipped defaults only.
  For all password authentication, collect success and failure outcomes from
  each authoritative authentication service where supported, regardless of
  default status. Distinguish attempted, rejected and successful authentication;
  do not infer the password used or its default status from a generic event.
* **Factory-default file and TPM credentials:** maintain an authenticated,
  versioned inventory of known factory-default public certificate fingerprints
  and public-key fingerprints, with product, image and phase applicability.
  Compare these against the identities actually configured for each consumer,
  including public identity retrieved through supported TPM or broker interfaces.
  A match establishes a known default identity is configured; it does not prove
  private-key possession, TPM residency or successful authentication. Verify
  key binding and TPM provenance separately where trusted evidence is available.
  An unmatched identity is not proof of uniqueness or non-default credentials.
  Never extract private keys or log PINs, tokens or secret values. A factory
  default PIN or opaque secret requires an authoritative read-only status from
  its owner; if unavailable, report unknown, not compliant, and do not attempt
  guesses that could trigger lockout. Distinguish permitted offline bootstrap
  identity from commissioned factory identity using the separate phase policy.
* **Certificates:** inspect the certificate actually configured for each
  service, its chain, validity period, issuer, intended key usage and identity.
  Report missing, expired, near-expiry, untrusted or unexpected identities.
  Avoid assuming that the newest file is the one a running process uses.
* **File-backed keys:** inspect configured key paths, file type, ownership,
  permissions, and policy-allowed storage. A policy requiring TPM backing must
  flag a file-backed key. Do not read or copy private-key contents for reports.
* **TPM-backed keys:** validate the configured key reference, phase, broker,
  access controls and available key provenance. A certificate or PKCS#11 URI
  alone does not prove TPM residency. Report `unknown` when evidence is
  insufficient rather than reporting compliance.

## Access and usage evidence

### File access

Use Linux Audit on the Host to observe selected certificate and key files for
reads, writes, metadata changes and denied access. Correlate kernel audit
records into complete events with process identity, executable, account,
operation, result, path and plane where determinable. Verify on the DUT how
audit paths and process identity behave across LXC mount and PID namespaces;
do not assume a Host path identifies the zone without evidence.

Use directory or rule management appropriate to the actual rotation strategy:
inode watches can become stale after atomic replacement. Reconcile rules after
rotation and zone recreation, and alert when watches or audit collection fail.
Bound event volume, queue use, disk retention and loss reporting. Reading a
public certificate or private-key file proves an access attempt, not that an
authentication or handshake succeeded.

### TPM signing

The existing MQTT, LDAP and rsyslog signing proxies are Host-side boundaries.
Verify whether their underlying PKCS#11 broker can expose per-request caller,
key identifier, operation and outcome. If it cannot, add instrumentation at a
verified trusted boundary; do not infer a successful signing operation merely
from a socket connection or service startup. Capture allowed and denied
requests without PINs, signing payloads or private key material. Restrict
direct TPM access so consumers cannot bypass the broker, and separately monitor
any approved direct TPM clients. Identify the caller using authenticated peer
credentials and account for namespace mapping.

### Authentication

Collect SSH and TLS service outcomes where the service emits reliable logs,
including identity and result when available. Correlate with certificate
fingerprints and broker/file events where possible. Correlation can be
ambiguous; report independent events when a reliable link is unavailable.
Zone journal collection is a prerequisite for zone-local authentication
coverage and is not supplied by Host `imjournal` alone.

Inventory password, file-key and TPM authentication consumers and their actual
event sources per plane, including direct TPM clients. Label each source as
covered, unavailable or unsupported, and report missing, stale or lost events.
A successful authentication event establishes use only when the source
identifies the authentication method and outcome reliably. A file open or a TPM
signing success is an operation, not proof of a successful authentication.

## Events and response

Use structured events internally, with stable fields: timestamp, device ID,
plane, service, policy version, event type, result, authentication method,
account, process identity, credential identifier or public-certificate
fingerprint, source and evidence quality when known. Use `unknown` for fields
the source cannot establish. Keep individual usage events distinct from
deduplicated compliance-state alerts; report dropped or aggregated usage events.
Never include passwords, shadow hashes, private keys, PINs, tokens,
certificate signing payloads or secret-bearing configuration values.

Suggested event types: `credential.default_password`,
`credential.password_login_state`, `certificate.expiring`,
`certificate.invalid`, `key.storage_mismatch`, `key.file_access`,
`key.sign_request`, `authentication.result`, and `monitor.health`. Send state
changes promptly and repeat active findings at a bounded interval; send
recovery events after remediation. The SIEM applies severity and correlation
rules. Monitoring must not change or block the service's credential operation.

Use the existing Host rsyslog local output and commissioned remote forwarding.
Verify durable queues, restart behavior and remote outage recovery; explicitly
report gaps, overflow and replay. Avoid recursive alert storms when forwarding
or the syslog signing broker fails.

## Security and operational constraints

Run the monitor with the minimum privilege needed for protected shadow and
certificate metadata. Separate privileged collection from policy evaluation
where practical. Use fixed allowlists and safe file traversal, reject symlink
and replacement races, bound parsing and output, and protect policy and local
state from unprivileged modification. Evaluate SELinux rules in enforcing mode;
do not treat permissive-mode success as sufficient. No hardcoded numeric role
IDs, credentials or server endpoints.

## Implementation and validation plan

1. Inventory live Host and zone identities, active services, brokers, auditd,
   rotation paths, journal access and SELinux labels. Produce a per-service
   mapping and distinguish observed behavior from assumptions.
2. Define policy and event schemas, account/phase handling, missing-evidence
   states and SIEM rules. Decide the scan interval, retention, alert thresholds
   and authorized readers from measured DUT behavior.
3. Implement a bounded password and certificate compliance scanner and
   authentication-event collection for supported services, followed by file-access
   audit rule reconciliation and broker event instrumentation only where the
   trusted boundary supports it. Report per-source coverage throughout.
4. Add a repeatable host or DUT test artifact under `tests/`, cross-linked here.
   Test default and changed passwords, authentication disabled, valid/expired
   certificates, unexpected issuer, TPM/file mismatches, unauthorized access,
   atomic key rotation, broker denial, missing evidence and audit loss.
   Include known-default and changed file/TPM public identities, unknown
   provenance, unavailable TPM, unsupported secret status, bootstrap versus
   commissioned phase, and successful-use evidence versus configured identity.
   Exercise successful and failed authentication using non-default passwords,
   file-backed keys and TPM-backed keys as well as defaults; verify source
   attribution, unsupported sources, collection loss and secret redaction.
5. Stage on the DUT before building. Verify all planes, password changes,
   commissioning and renewal, event attribution, SIEM receipt, service health,
   queue recovery and SELinux AVCs. Exercise enforcing mode safely and confirm
   least-privilege policy before declaring completion.

## Side Effects & Caveats

Audit reads can be noisy and may expose operational metadata; tune policies and
retention based on measured traffic. Periodic TPM checks can increase broker
load and connection pressure, so prefer passive evidence and rate limits.
File access does not establish successful use, and no mechanism can reliably
attribute activity if its logs or trusted peer identity are unavailable. Zone
logs, direct TPM clients and audit queue loss are explicit coverage gaps until
verified. Existing services, provisioning and password-login controls must
continue to work throughout monitoring failures.
