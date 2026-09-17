# EPRTrack V6 — working account + dashboard flow

## Product flow
Calculator → Save & Track → account creation/sign in → dashboard → company → saved calculator record.

## Authentication
- Passwords are never stored in plaintext.
- Passwords are stored as salted PBKDF2-HMAC-SHA-256 hashes.
- V6 uses 100,000 iterations as a Cloudflare Workers Free-plan-friendly baseline. OWASP currently recommends 600,000 PBKDF2-HMAC-SHA-256 iterations where PBKDF2 is used; upgrade the work factor when the Worker has sufficient CPU budget.
- Sessions are server-side in D1 with 256-bit cryptographically random IDs.
- Browser authentication uses a `__Host-` Secure, HttpOnly, SameSite=Strict cookie.
- Authentication tokens are not stored in localStorage.
- D1 queries use prepared statements with bound parameters.

## D1
Expected tables/columns:
- users(id,email,password_hash,created_at)
- sessions(id,user_id,expires_at)
- companies(id,user_id,legal_name,role,category,state,fy,created_at,updated_at)
- compliance_profiles(company_id,input_tonnes,epr_target_tonnes,recycling_required_tonnes,recycled_content_rate,progress_tonnes,rule_version,source_url,verified_on)

Keep the real production `wrangler.jsonc` and D1 binding. This package intentionally does not include it.

## Save & Track routing
`/save-track/` is handled by the Worker. Signed-in users are redirected to `/dashboard/`; signed-out users are redirected to `/auth/?mode=register&next=/dashboard/`.

## Payment
Payment/subscription checkout is intentionally disabled in V6. Pricing is informational only. Add Razorpay after the account and dashboard flow has been tested.

## Testing checklist
1. Create a new account.
2. Confirm the account lands on dashboard.
3. Create a company.
4. Confirm a pending calculator result is saved.
5. Sign out.
6. Sign back in with the same credentials.
7. Confirm the dashboard and saved record load.
8. Click Save & Track while already signed in and confirm it goes directly to dashboard.
