# Security deployment checklist

## Required before production use

1. In Render Environment, configure `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID`, `SUPABASE_URL`, and `SUPABASE_KEY`. OTP verification now fails closed when Twilio is missing; there is no demo-code bypass.
2. Configure each Chief/Sarpanch password hash as a Render secret named `SARPANCH_PASSWORD_HASH_<VILLAGE_KEY>` for the keys KALYANI, DEOKHALIYA, MASAULI, CHHATAUNI, RASAULI, SATRIKH, RAMPUR, FATEHPUR, SAFEDABAD, NAWABGANJ, BADOSARAI, and ZAIDPUR. Values must use `salt_hex:digest_hex`, generated with the `hash_password` helper in a trusted administrative environment. Do not commit hashes or passwords to source. All privileged logins remain disabled until hashes are configured.
3. Rotate any previously exposed Sarpanch passwords and invalidate any old credentials.
4. Verify Supabase RLS is enabled for `farmers` and `weather_feedback_log`; use least-privilege policies and never expose a service-role key to browser/client code. This cannot be verified from this repository alone.
5. Configure HSTS, CSP (start with Report-Only), `X-Content-Type-Options`, `Referrer-Policy`, frame restrictions, and `Permissions-Policy` at a supported reverse proxy/edge layer if Render's service configuration does not provide response-header rules. Verify with `curl -I https://<deployment-host>/`; do not assume app comments or Streamlit config set headers.
6. Apply a shared rate limiter (e.g. Redis-backed) for OTP send/verify and privileged login before public production use. Current Streamlit session-state throttling is not global.
7. Run `bandit -r .`, `pip-audit -r requirements.txt`, and a secret scanner in CI; pin reviewed dependency versions after testing compatibility.

## Hash provisioning

From a trusted local administrative Python session, import `hash_password` only after installing the project's dependencies and generate a salted hash for each newly chosen strong password. Set the resulting string as the corresponding Render environment secret. Do not print it into logs or commit it.

## Known limitations

This source bundle does not include Render dashboard settings, Supabase policy definitions, the original scanner name/report, or deployment credentials. Therefore live headers, RLS, CORS, deployment environment variables, and the original 85/100 score remain unverified.
