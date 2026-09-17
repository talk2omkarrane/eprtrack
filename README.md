# EPRTrack V3 — Save & Track

This package upgrades the deployed EPRTrack V2 public SEO layer with the first working product loop:

**Calculator → Save & Track → account → company → saved compliance record → dashboard.**

## Important
- This package intentionally does **not** include `wrangler.jsonc`. Keep the real Cloudflare configuration and D1 database binding from the existing repository.
- Do not overwrite your existing D1 binding or production `wrangler.jsonc`.
- The backend expects the existing D1 tables for `users`, `sessions`, `companies`, and `compliance_profiles`.
- The saved calculator record is an indicative planning record; it does not claim to determine the legal EPR target.
- Passwords are hashed with PBKDF2-SHA-256 before storage. Sessions use bearer tokens stored in D1 and expire after 30 days.

## Files to copy into the existing repository
Copy/replace: `src/index.js`, `package.json`, `public/styles.css`, `public/calculator/index.html`, and add `public/auth/index.html` and `public/dashboard/index.html`.

## Existing D1 compatibility
The code uses the current EPRTrack-style fields:
- `users(id,email,password_hash,created_at)`
- `sessions(token,user_id,expires_at)`
- `companies(id,user_id,legal_name,role,category,state,fy,created_at,updated_at)`
- `compliance_profiles(company_id,input_tonnes,epr_target_tonnes,recycling_required_tonnes,recycled_content_rate,progress_tonnes,rule_version,source_url,verified_on)` with a unique `company_id`.

If your production D1 schema differs, stop before deployment and reconcile the schema rather than guessing.

## Flow
1. User calculates a result.
2. `Save & track` stores the result temporarily in browser local storage and opens `/auth/`.
3. User signs in or creates an account.
4. Dashboard asks for the company profile.
5. The calculator result is saved against that company.
6. Dashboard displays the saved planning quantity, recycled-content rate, indicative quantity, and tracked progress.

## Security notes
- API endpoints require a bearer session except registration, login, logout, health, and the public calculator.
- Company ownership is checked before reading/writing compliance records.
- This V3 still uses localStorage for the bearer token; before a larger production rollout, consider migrating to secure HttpOnly cookie sessions with CSRF protection.


## Authentication security
- Passwords are never stored in plaintext. They are stored as PBKDF2-HMAC-SHA-256 hashes with a unique 128-bit salt and 600,000 iterations.
- Sessions use 256-bit cryptographically random identifiers stored server-side in D1.
- The browser receives only a Secure, HttpOnly, SameSite=Strict session cookie; no authentication token is stored in localStorage.
- D1 encrypts stored data at rest and Cloudflare Workers-to-D1 traffic uses TLS.
- Authenticated state-changing API requests enforce same-origin requests.
- This is an application-level baseline, not a substitute for production rate limiting, email verification, password reset/recovery, monitoring, or Cloudflare WAF/rate limiting.
