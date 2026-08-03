# entra-sms-voice-mfa-report

Find every user in a Microsoft Entra ID tenant who has a phone number registered as an authentication method, before Microsoft-provided SMS and Voice stop working on **1 February 2027**.

Read-only. One script, no dependencies beyond `Microsoft.Graph.Authentication`, and two outputs: a CSV for the people doing the work and a self-contained HTML report for the people asking about it.

---

## Why this exists

Microsoft is retiring Microsoft-provided SMS and voice call delivery for MFA and SSPR. From 1 September 2026, users enabled for those methods are auto-enabled for passkeys and prompted to register. From 1 February 2027, the methods stop working.

The awkward part is that Entra does not store "SMS" and "Voice" as two separate registrations. It stores a phone number with a type, and the type decides what it can do:

| Registered type | SMS | Voice call |
|---|:--:|:--:|
| `mobile` | Yes | Yes |
| `alternateMobile` | No | Yes |
| `office` | No | Yes |

So there is no clean "SMS users vs Voice users" split to report. This script reports what the directory actually holds, and tells you which users can receive SMS rather than inventing a distinction that does not exist.

## What you get

**Console summary** — the headline numbers, including the one that matters: users whose *only* MFA method is a phone.

```
  Users checked                            4,182

  USERS WITH SMS OR VOICE REGISTERED         240
     of which can receive SMS                 87
     privileged accounts                      14

  NO OTHER MFA METHOD - act first             74
```

**CSV** — sorted by priority, so the top of the file is the work queue.

**HTML report** — self-contained, no CDN, no network calls. Countdown to the retirement date, priority breakdown, milestone timeline, and a searchable table with filters and an "export current view to CSV" button. Opens in any browser and prints cleanly to PDF.

Every affected user gets one of three priorities:

| Priority | Meaning | Action |
|---|---|---|
| **P1** | Phone is the only MFA method | Register an alternative **before** removing the phone. These users are blocked at sign-in after 1 Feb 2027. |
| **P2** | Has an alternative, phone still default | Change the default, then remove the number. |
| **P3** | Alternative in place and already default | Remove the number. No user impact. |

## Quick start

```powershell
Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser

.\Get-SmsVoiceMfaUsers.ps1 -TenantId contoso.onmicrosoft.com `
                           -CustomerName "Contoso Ltd" `
                           -OutputFolder C:\Reports\Contoso
```

> **Always pass `-TenantId` when working across multiple tenants.** It is what stops the script reusing a Graph session left over from a previous tenant.

Full instructions: [docs/RUNBOOK.md](docs/RUNBOOK.md) — also available as a [PDF](docs/RUNBOOK.pdf) for sharing.

## Permissions

| Scope | When | Why |
|---|---|---|
| `AuditLog.Read.All` | Always | Reads `/reports/authenticationMethods/userRegistrationDetails` |
| `UserAuthenticationMethod.Read.All` | Only with `-IncludePhoneNumbers` | Reads each affected user's phone method |

Entra role: Global Reader, Security Reader, or Reports Reader.

**No write scope is ever requested.** The script issues GET requests only — verifiable with `Select-String -Pattern '-Method (?!GET)' Get-SmsVoiceMfaUsers.ps1`.

## Parameters

| Parameter | Effect |
|---|---|
| `-TenantId` | Tenant GUID or domain. Validates the session belongs to the right tenant. |
| `-CustomerName` | Organisation name in the HTML header. Auto-detected if omitted. |
| `-OutputFolder` | Output location. Default: current directory. |
| `-OutputFormat` | `CSV`, `HTML`, or `Both`. Default: `Both`. |
| `-IncludePhoneNumbers` | Adds masked phone numbers. Slower, needs the extra scope. |
| `-ExcludeGuests` | Omits B2B guest accounts. |
| `-KeepSession` | Leaves the Graph session connected after the run. |
| `-NoFilePermissionHardening` | Skips the restrictive ACL on output files (Windows). |

## Security notes

This is designed to be run against tenants you do not own, so a few things are deliberate:

- **Tenant validation.** The script refuses to reuse an existing Graph session that belongs to a different tenant. Without this, running against two tenants in one session can silently produce a report from the wrong one.
- **CSV formula injection guarded.** Display names are attacker-influenced — a guest brings their own. Values starting with `=` `+` `-` `@` are prefixed so Excel treats them as text rather than executing them.
- **HTML output is injection-safe.** Data is embedded as escaped JSON and rendered through an escaping function; tested against XSS payloads in display names.
- **Session teardown.** Disconnects on completion unless `-KeepSession` is passed.
- **Output hardening.** Restrictive ACL on Windows, phone numbers masked by default with no unmask option.
- **Fails loudly.** An empty report throws rather than reporting a clean tenant, so a missing consent cannot look like good news.

See [SECURITY.md](SECURITY.md) for reporting issues.

### Before you run this against a client

- [ ] Test end-to-end in a lab tenant first
- [ ] Code-sign the script and publish the hash if you are distributing it
- [ ] Read [docs/RUNBOOK.md](docs/RUNBOOK.md) section 7 on handling the output — it contains personal data

**Do not commit output files.** `.gitignore` excludes `*.csv` and generated reports, but check before you push.

## Known limitations

- The registration report is generated data and can lag the directory by a few hours. Use `-IncludePhoneNumbers` for point-in-time truth on a specific user.
- `-IncludePhoneNumbers` makes one Graph call per affected user. Slow above a few thousand users; `$batch` support is on the roadmap.
- Reports on *registered* methods. Users **enabled** for SMS/Voice in the Authentication Methods Policy is a different, usually larger set — check that separately for September 2026 auto-enablement scope.

## Roadmap

- [ ] Graph `$batch` for phone-number lookups
- [ ] Last sign-in date, to separate dormant accounts from real remediation work
- [ ] Department and manager, to make the list assignable
- [ ] Baseline and delta mode for tracking a campaign over time
- [ ] App-only certificate authentication for scheduled runs

Not affiliated with or endorsed by Microsoft. Provided as-is; test in a lab tenant before production use.
