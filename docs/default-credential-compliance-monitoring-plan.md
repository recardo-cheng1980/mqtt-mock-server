# Continuous credential usage and default compliance monitoring

Status: proposal; implementation, coverage inventory and DUT validation are pending.
This develops the usage and default-credential portions of the broader
[credential monitoring design](credential-compliance-monitoring-design.md).

## Goal and scope

Monitor password, file-backed and TPM-backed credential operations and
authentication outcomes regardless of default status. Separately detect known
factory or image-default credentials that remain usable, and report confirmed
authentication with a known default only when the authentication owner can
provide that evidence. Cover Host, IT, DMZ and OT local accounts and WebUI
accounts first, and extend coverage to file-backed and TPM-backed identities.
Inventory other active services and their credential authorities
before claiming coverage; LDAP, external systems and opaque password stores need
their own supported interfaces. An uninspectable authority is unknown, not compliant.

## Proposed design

1. Maintain a versioned, root-controlled policy inventory of plane, service,
   authority, account, applicable image/vendor default identifiers and approved
   source. Resolve names using the owning plane's context, not fixed numeric UID. Defaults
   must come from an authoritative versioned source; never invent candidates or
   record unique provisioning secrets. Explicitly identify retired defaults that
   remain relevant after upgrades.
2. Run bounded read-only checks at boot and periodically (initial proposal: hourly),
   plus after known password, configuration, provisioning, reset and zone lifecycle
   events. A periodic full reconciliation covers missed notifications. Define a
   maximum scan duration, retry/backoff and freshness threshold; missing or stopped
   required planes and failed sources produce unknown and health alerts.
3. For local shadow-backed accounts, a narrowly scoped Host-side privileged
   checker compares only authoritative known default candidates using the stored
   hash algorithm and salt, without interactive login attempts. Validate algorithm
   support and resource limits. A locked, empty, malformed or unsupported hash has
   an explicit state; never label an unsupported hash compliant. Determine password
   login exposure separately from credential match, including account lock/expiry
   and each relevant authentication path. A default can remain present even when a
   particular login path is disabled.
4. WebUI and other non-shadow authorities require owner-provided, read-only
   compliance status or an equivalent verified interface. The existing WebUI
   `Default_PWD` authentication result can signal an observed default login at
   the point of authentication, but does not itself provide a periodic inventory.
   Do not replay passwords against live authentication endpoints or infer success
   from a login event alone. Explicitly account for each supported authority's
   defaults, disabled accounts and provisioning lifecycle.
5. The Host collects and checks every zone source it can access reliably through
   an approved interface. Add a plane-owned adapter only for a specific source
   proven inaccessible or unreliable from the Host but available inside that
   plane. A zone may need no adapter. Any necessary adapter returns bounded,
   non-secret results over an authenticated, access-controlled interface; verify
   namespace identity and lifecycle behavior. The Host emits state changes,
   recovery, bounded reminders and health events to its journal and existing
   rsyslog path. Verify queueing, delivery and loss reporting.
6. Maintain an authenticated, versioned inventory of known factory-default
   certificate and public-key fingerprints and their product, image and phase
   applicability. Check the identity configured for each service, including public
   identities exposed through supported TPM or broker interfaces. A match identifies
   a configured default identity, not successful use, private-key possession or TPM
   provenance; establish those separately where trusted evidence exists. An unmatched
   fingerprint is not proof of a unique or non-default key. Factory-default TPM PINs
   and other opaque secrets need an authoritative read-only status from their owner;
   otherwise report unknown. Do not try PINs or extract private keys. Evaluate
   offline bootstrap and commissioned identity under their distinct phase policies.
7. Inventory all credential consumers and their available event sources per plane.
   Capture successful and failed password authentication, file-key access and
   TPM signing operations, and authentication outcomes where the owning service
   provides trustworthy evidence, for both default and non-default credentials.
   Mark missing, unsupported and stale sources as coverage gaps. Correlate only
   when reliable identifiers exist: file access or a successful TPM sign alone
   does not establish successful authentication. Do not record entered passwords,
   key contents, PINs or signing payloads.

## Host and zone responsibility

The Host owns inventory, scheduling, account and credential compliance checks,
Linux Audit collection, Host TPM broker events, collection of authentication
events available from the Host, correlation, forwarding and monitoring health.
Host journal collection does not by itself cover zone journals: investigate a
safe Host-accessible journal interface first. Verify attribution across mounts,
namespaces and zone restarts, and report gaps where collection is not reliable.

Zone-specific code is conditional, not a default requirement. For each proposed
task, record the source, why an approved Host interface cannot obtain it reliably,
what the zone can establish, and the smallest non-secret result interface. An
example is an authority that exposes a necessary read-only status only through a
zone-local interface, but this remains hypothetical until verified. Authentication
events are collected by the Host wherever possible; any required source-side
instrumentation belongs to its owning service and does not justify a general
zone checker. No task is currently proven to require a checker in any zone.

The DUT exposed the three merged zone `/etc/shadow` paths to Host root. Verify
live mount resolution, race handling, zone lifecycle and SELinux enforcing access
before relying on those paths. File visibility alone does not prove safe or
complete monitoring.

## Result semantics

Per authority/account, expose `default_present`, `default_absent`, `unknown` or
`not_applicable`, separately from `login_enabled`, `login_disabled` or `unknown`
per path. An authentication owner may additionally emit `default_login_success`
or `default_login_rejected` only when it can establish the candidate was the
default and report the actual outcome. A default-present finding is a configuration
risk, not proof of a login; absence of a default match only covers inventoried
known defaults, not password strength or previously observed use.

Events include device, plane, authority, account, check or event time, policy
version, event type, operation, outcome, authentication method, credential type,
evidence source and error category when known. Identify unavailable fields as
unknown. Preserve individual usage events separately from deduplicated compliance
alerts and report any collection loss or aggregation. Never emit password candidates,
password hashes, shadow records, tokens or other secret values. Restrict local
state and policy modifications; bound output, rate and retention. Monitoring must
not reset credentials, alter expiry or block authentication. Separate bootstrap and
commissioned TPM phases and never infer factory credentials from bootstrap state.

## Feasibility and implementation plan

The current DUT has auditd and rsyslog active and SELinux permissive; this alone
does not prove event delivery, zone coverage or access under enforcing mode. The
existing unique initial password plan in the UCT-IQ9075 repository
describes per-device provisioning and independent subsequent plane changes. WebUI
login code recognizes `Default_PWD`; its authoritative periodic inspection
interface and all other supported credential stores remain to be verified.

1. Inventory active authorities, default provenance and upgrades, authentication
   paths, zone lifecycle and current events without exposing credentials. Verify
   safe APIs, shadow hash algorithms, performance and SELinux labels/AVCs. Mark
   unsupported authorities unknown and settle interfaces before implementation.
2. After approval, add Host-owned collection and aggregation under the owning
   `meta-wnc` recipes, with explicit dependencies, bounded timers, policy, state
   and least-privilege SELinux policy. Add a zone-owned adapter only after the
   Host-accessibility test above proves it necessary. Exact files depend on the
   inventory and must be finalized before code changes. Add owner-generated
   authentication evidence only where the actual outcome can be proven.
3. Add repeatable host tests under `tests/host/` and, as needed, a DUT suite under
   `tests/dut/default-credential-compliance/` with a README linking this plan.
   Test default, changed, locked, expired, disabled, unsupported/malformed hashes,
   unknown authorities, stale and missing planes, rotations, restarts, event loss,
   redaction, known-default and changed file/TPM identities, unavailable TPM,
   unsupported PIN status, phase transitions, and actual default-login
   success/rejection separately. Exercise non-default password authentication,
   file-key and TPM operations, authentication outcomes and source loss. Use synthetic
   fixtures, never production credentials. Link completed tests here.
4. Stage and exercise safely on the DUT before any build, inspect service health,
   logging and AVCs, and verify the required permissions in enforcing mode. Verify
   SIEM receipt and outage recovery where available; record observed test output.
   Only then run the authorized image build. A missing DUT validation or required
   test artifact blocks the build.

## Side Effects & Caveats

- Protected password verification requires carefully constrained privilege and
  may consume CPU; bound checks and do not expose offline-cracking material.
- Hourly scans leave a detection window; event notifications reduce but cannot
  eliminate it. Actual default use is observable only at instrumented authorities.
- Zone unavailability, unsupported stores, stale policy, unverified forwarding and
  unknown authentication paths are visible coverage gaps, never passes.
- SELinux is currently permissive; required enforcing rules cannot be specified
  safely until implementation-specific AVCs and labels are observed.
- The initial interval, retention, eligible services and event transport are
  design assumptions requiring operational and DUT validation.
- Host-side access to zone credential stores increases Host collector privilege;
  constrain it, avoid exporting hashes, and validate SELinux and lifecycle races.
