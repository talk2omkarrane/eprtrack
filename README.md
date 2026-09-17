# EPRTrack V11 — Compliance workspace redesign

V11 keeps the working V8 auth/D1 schema compatibility and redesigns the dashboard around the actual SaaS value proposition.

## Dashboard tracking
- Company workspace
- Verified EPR target input
- Achieved/credited quantity input
- Target vs achieved progress
- Shortfall calculation
- Calculator planning snapshot kept separate from legal target
- Next-action workflow
- Responsive layout for desktop/tablet/mobile

## Product positioning
Free = one-time planning calculator.
Paid = recurring compliance workspace: FY records, target/achieved tracking, deadlines, evidence/certificate records, regulatory alerts and reports.

## Payments
Payment/checkout remains disabled. Pricing is informational only until product testing is complete.

## Important regulatory boundary
EPRTrack does not invent legal EPR targets. Users enter a verified target from their official CPCB records in this phase. The public calculator remains an indicative planning aid.

Keep the existing real wrangler.jsonc and D1 binding. Do not replace it with a package file.


V10 workspace behavior: one company workspace per account during testing; legacy multiple company records remain selectable for test-data compatibility. Pending calculator results are automatically saved to the active company after sign-in. Payment remains disabled.


## V11 compliance checklist
- Adds a recurring compliance checklist stored in D1 per company.
- Seeds four starter tasks: verify target, record achieved quantity, prepare annual return, and review CPCB updates.
- Annual-return starter date is based on the notified 30 June next-financial-year guideline for Producers, Importers and Brand Owners; CPCB extensions can change actual filing dates.
- Users can add, complete, and reopen company-specific tasks.
- Task sources are shown where a source URL is available.
- A separate `workspace_tasks` table is created automatically; no wrangler configuration change is required.
- Payment remains disabled.
