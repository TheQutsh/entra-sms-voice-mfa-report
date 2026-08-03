# Runbook — SMS & Voice MFA Registration Report

**Script:** `Get-SmsVoiceMfaUsers.ps1`
**Purpose:** Identify every user in a Microsoft Entra ID tenant who has a phone number registered as an authentication method, ahead of the Microsoft-provided SMS and Voice retirement on **1 February 2027**.
**Access required:** Read-only. The script issues GET requests only and never requests a write scope.

---

## 1. Before you start

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or PowerShell 7.x |
| Module | `Microsoft.Graph.Authentication` 2.0.0 or later |
| Entra role | Global Reader, Security Reader, or Reports Reader |
| Network | Outbound HTTPS to `graph.microsoft.com` |
| Time to run | 1–2 minutes for a standard run; add ~1 minute per 500 users if `-IncludePhoneNumbers` is used |

**Install the module (one time):**

```powershell
Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.0.0 -Scope CurrentUser
```

If the tenant blocks PSGallery, install from the organisation's internal repository instead.

---

## 2. Permissions to approve

The script asks for consent to the following delegated scopes. Share this table with whoever approves the consent prompt.

| Scope | When requested | Why |
|---|---|---|
| `AuditLog.Read.All` | Always | Reads `/reports/authenticationMethods/userRegistrationDetails` — the registered-methods report |
| `UserAuthenticationMethod.Read.All` | Only with `-IncludePhoneNumbers` | Reads each affected user's phone method to return the number |

No write, directory-modify, or mail scope is ever requested. If an admin consent prompt shows anything beyond the two scopes above, stop and investigate.

---

## 3. Run it

**Standard run** — produces both a CSV and an HTML report in the current folder:

```powershell
.\Get-SmsVoiceMfaUsers.ps1
```

**Recommended for a client engagement** — pin the tenant explicitly and name the output:

```powershell
.\Get-SmsVoiceMfaUsers.ps1 -TenantId contoso.onmicrosoft.com `
                           -CustomerName "Contoso Ltd" `
                           -OutputFolder C:\Engagements\Contoso
```

> **Always pass `-TenantId` when you work across multiple tenants.** It is what stops the script reusing a Graph session left over from a previous client. Without it, the script will use whatever session is already open.

A browser window opens for sign-in. Sign in with an account holding one of the roles listed in section 1.

### Parameters

| Parameter | Effect |
|---|---|
| `-TenantId` | Tenant GUID or domain. Validates the session belongs to the right tenant. |
| `-CustomerName` | Organisation name shown in the HTML header. Auto-detected if omitted. |
| `-OutputFolder` | Where files are written. Default: current directory. |
| `-OutputFormat` | `CSV`, `HTML`, or `Both`. Default: `Both`. |
| `-IncludePhoneNumbers` | Adds masked phone numbers. Slower, needs the extra scope. |
| `-ExcludeGuests` | Omits B2B guest accounts. |
| `-KeepSession` | Leaves the Graph session connected after the run. |

---

## 4. Read the output

### Console summary

```
  Users checked                            4,182
  USERS WITH SMS OR VOICE REGISTERED         240
     of which can receive SMS                 87
     privileged accounts                      14
  NO OTHER MFA METHOD - act first             74
```

The last line is the number that drives the remediation plan.

### Priority column

Every affected user is assigned one of three priorities. The CSV is sorted by it, so the top of the file is the work queue.

| Priority | Meaning | What to do |
|---|---|---|
| **P1** | Phone is the user's only MFA method | Register an alternative (passkey or Authenticator) **before** removing the phone. These users are blocked at sign-in after 1 Feb 2027. |
| **P2** | Has an alternative, but phone is still the default | Change the default method, then remove the number. |
| **P3** | Alternative already in place and already default | Remove the phone number. No user impact. |

### Files produced

| File | Audience | Use |
|---|---|---|
| `SMS-Voice-MFA-Users-<date>.csv` | Operations / helpdesk | Working list, filter and assign |
| `SMS-Voice-MFA-Report-<date>.html` | Management / CISO | Self-contained report; open in any browser, `Ctrl+P` for PDF |

The HTML report has a search box, priority filters, sortable columns, and an **Export current view to CSV** button — filter to P1, export, and that is the helpdesk queue.

### Understanding the SMS and Voice columns

Entra does not store SMS and Voice as two separate registrations. It stores a phone number with a type:

| Registered type | Can receive SMS | Can receive voice call |
|---|---|---|
| Mobile | Yes | Yes |
| Alternate mobile | No | Yes |
| Office | No | Yes |

Every user in the report is in scope for the retirement, regardless of type.

---

## 5. Key dates

| Date | What happens |
|---|---|
| 1 Sep 2026 | Users enabled for SMS or Voice are auto-enabled for passkeys and prompted to register at next MFA. The prompt can be dismissed. |
| 18 Sep 2026 | Microsoft publishes supported third-party telecom providers. |
| 30 Oct 2026 | Organisations still needing SMS or Voice must have a provider configured. |
| 1 Feb 2027 | Microsoft-provided SMS and voice stop working, including for SSPR. |

Note that the September auto-enablement targets users **enabled** for SMS or Voice in the Authentication Methods Policy — usually a larger set than the users who happen to have a number registered. Check the policy separately if you need that scope.

---

## 6. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `The registration report returned no records` | Consent or role missing. Confirm `AuditLog.Read.All` is consented and the account holds Global Reader, Security Reader, or Reports Reader. This is an error, not a clean tenant. |
| `Existing Graph session does not match this request. Reconnecting.` | Expected and correct. A session from another tenant was open; the script disconnected it. |
| `Microsoft.Graph.Authentication X is installed; 2.0.0 or later is required` | Run `Update-Module Microsoft.Graph.Authentication`. |
| `N of M phone-number lookups failed` | Missing `UserAuthenticationMethod.Read.All`, or throttling. User counts are still correct; only the number column is affected. |
| Script will not run — execution policy | Preferred: use a signed copy. Temporary: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. Do not change machine-wide policy. |
| Counts shift slightly between runs | The registration report is generated data and can lag the directory by a few hours. Normal during active remediation. |

---

## 7. Handling the output

The CSV and HTML contain personal data: display names, user principal names, privileged-role status, and — if `-IncludePhoneNumbers` was used — masked phone numbers.

- Store in the engagement's approved location only.
- Transfer via the client's approved channel, not personal email or messaging.
- Apply the retention period in the engagement's data-protection terms; delete on closure.
- Numbers are masked by default. There is no unmask option in this version by design.

On Windows the script automatically restricts file permissions to the account that ran it.

---

## 8. Before standardising across clients

- [ ] Run end-to-end in a lab tenant, both with and without `-IncludePhoneNumbers`
- [ ] Verify the cross-tenant guard by running against two tenants in one session
- [ ] Run `Invoke-ScriptAnalyzer -Severity Warning,Error` and clear findings
- [ ] Test with an under-privileged account to confirm it fails loudly
- [ ] Code-sign the script and publish its SHA256 hash
- [ ] Have a second engineer review it

---

*Data source: Microsoft Graph `/reports/authenticationMethods/userRegistrationDetails`.*
