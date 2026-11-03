# Our Baby Plan 👶💞

A private, password-protected conception journal for couples: it predicts the fertile window, tells you the best days to try, tracks signs (temperature, ovulation tests, cervical mucus), and builds daily diet & exercise habits for both partners.

## Features
- **Private login:** data is encrypted (AES-256-GCM, key from your password via PBKDF2-SHA256, 310k iterations) and stored in this browser. Nothing leaves the phone unless you turn on sync, and then only encrypted data. Auto-locks when idle; attempts are throttled after 5 wrong passwords.
- **Today screen:** fertility level (period / low / fertile / peak / two-week wait), cycle day, estimated ovulation, next period, best days to try, and when to take a pregnancy test.
- **Smarter predictions:** learns your average cycle from logged periods, widens the window for irregular cycles, uses a positive ovulation test (ovulation ≈ next day) and confirms ovulation from a temperature rise (3-over-6 rule).
- **Calendar** with colour-coded fertile/peak days, plus cycle history.
- **Daily journal:** temperature, mucus, ovulation test, pregnancy test, mood, symptoms, intercourse, notes from both partners, temperature chart.
- **Diet & fitness:** nutrients for her & him, foods to avoid, 7-day Indian meal plan (veg + non-veg swaps), supplements to discuss with your doctor, weekly exercise plan, BMI check, daily habit checklist & weekly score.
- **Pre-conception checklist** (tests, vaccines, screening, insurance) and a "months trying" tracker that tells you when to see a specialist (6 months when she is 35+).
- **Sync between both phones:** turn it on in Settings → *Sync between phones* and tap **Show QR**. On the other phone choose *Join my partner's journal* → **Scan QR** (camera) or **Upload QR image** (screenshot) — or just point the phone's normal camera at the QR — then enter the same journal password. The text sync code (Copy/Share) still works too. Changes from either phone merge field-by-field (newest wins) within seconds, and work offline.
  End-to-end encrypted: only ciphertext is stored in Supabase (`journey_vaults` table, reachable only through `journey_pull` / `journey_push` / `journey_delete` functions that check a password-derived token).
- **Encrypted backup/restore** to move to another phone.

## Use it
**Vercel:** vercel.com → Add New → Project → import `MyJourney` → Framework preset "Other", no build command → Deploy. Security headers are set in `vercel.json`.

Open `index.html` in a browser, or host free on **GitHub Pages** (Settings → Pages → deploy from this branch) and open it on your phone, then "Add to Home Screen".

> ⚠️ There is no password reset. If you forget it, the data can't be recovered — download backups regularly.

Predictions are estimates, not medical advice and not contraception. Please see your doctor.

## Third-party code
Bundled in `vendor/` and loaded only when a QR code is shown or scanned:
- [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 — MIT, © Kazuhiko Arase
- [jsQR](https://github.com/cozmo/jsQR) 1.4.0 — Apache-2.0 (see `vendor/jsQR-LICENSE.txt`)
