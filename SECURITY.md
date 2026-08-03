# Security Policy

## Scope

This repository contains a read-only reporting script that authenticates to Microsoft
Entra ID via Microsoft Graph. It issues GET requests only and never requests a write scope.

Because it is designed to be run by consultants against customer tenants, the threat model
includes:

- Cross-tenant data disclosure (producing a report from the wrong tenant)
- Injection through directory data — display names and UPNs are attacker-influenced
- Personal data left on disk or accidentally committed to source control
- Over-broad consent requests

## Using this safely

**Before running against a customer tenant**

- Test in a lab tenant first
- Verify the script hash against the release, or use a copy you have code-signed yourself
- Pass `-TenantId` explicitly so the tenant guard can validate the session
- Confirm the consent prompt shows only the scopes documented in the README — anything
  else means the script has been modified

**Handling output**

Output files contain display names, user principal names, privileged-role status and,
if `-IncludePhoneNumbers` was used, masked phone numbers. Treat them as personal data:
store in the engagement's approved location, transfer over approved channels, and delete
per the applicable data-protection terms.

Phone numbers are masked by default and there is no unmask option by design.

**Do not commit output.** `.gitignore` excludes `*.csv` and generated reports, but verify
before pushing. If customer data is committed, rewriting history is not sufficient —
treat it as a disclosure and follow your incident process.

## Supported versions

Only the latest release receives fixes.
