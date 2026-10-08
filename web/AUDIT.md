# Security Audit — PTR Validator Web

**Date:** 2026-09-30
**Scope:** every file in the project folder: `verify.php`, `user_data.php`, `import_api.php`, `import_tool.html`, `index.html`, `includes/*.php`, `config.php`, SQL scripts, `example_data/`.
**Method:** manual code review. Nothing was run (PHP is not installed on the review machine), and the live site was not tested.
**Out of scope:** NTAG424 SDM/CMAC verification (`includes/ntag424_sdm.php`). It is known to be non-functional and intentionally disabled for now. Review it separately before enabling it.

## Summary

| ID | Severity | Finding |
|----|----------|---------|
| C1 | Critical | Any `card_uid` value unlocks full member details and allows database writes |
| C2 | Critical | Member records can be enumerated and scraped (combined with C1) |
| H1 | High | Personal data workbook sits in the project folder |
| H2 | High | Secrets stored in plain text in `config.php` |
| H3 | High | Test page `index.html` and helper files would be public if uploaded |
| M1 | Medium | Import password remembered in `localStorage` of a `file://` page |
| M2 | Medium | SheetJS 0.18.5 from a CDN: known CVEs, no integrity check |
| M3 | Medium | Import can overwrite or clear data for all members, with no backup or audit trail |
| M4 | Medium | No rate limiting on the public lookup endpoints |
| L1 | Low | Import lockout is per-IP in a shared temp directory |
| L2 | Low | CORS on `import_api.php` reflects any origin with credentials |
| L3 | Low | Missing security and cache headers |
| L4 | Low | Non-numeric member numbers match member `0` |
| L5 | Low | Verified response exposes more fields than needed |
| I1 | Info | Hosting and RODO compliance |

What is done well: all SQL uses prepared statements, all HTML output is escaped (`htmlspecialchars`), exceptions are logged instead of shown, the import password is compared in constant time, import writes are transactional, and the import tool never sends names, addresses, phones, e-mails or remarks.

---

## Critical

### C1. Any `card_uid` value unlocks full member details and allows database writes

`includes/membership_service.php:65`

```php
$verified = ($cardUID !== null); //ntag424CheckReplayAndBinding($member, $sdmResult);
```

While NTAG verification is disabled, "verified" only means a `card_uid` parameter was present. Its value is never compared with the member's stored UID.

- `verify.php?member_id=123&card_uid=x` (or `user_data.php?...`) returns the full record for member 123, including `card_uid`, `membership_type`, the expiration date and the free-text `info`.
- Every such request writes to the database through a plain GET with no authentication:
  - `updateLastReadCounter()` (line 73) sets `last_read_counter` to 0, because the SDM result has no counter.
  - `assignCardUid()` (lines 68–69) binds `sdmResult['card_uid']` to members with no card yet. `ntag424VerifySdm()` returns the attacker-supplied `uid` even when the CMAC does not match. So `?member_id=N&card_uid=x&uid=<14 hex>&ctr=1&cmac=<16 hex>` permanently binds an arbitrary UID. The unique index on `card_uid` then blocks the real card from ever binding.

**Fix (until NTAG works):**
- Treat a request as verified only when `card_uid` is present **and** matches the stored `members.card_uid` (`strcasecmp`, only if the stored value is non-empty).
- Do not call `assignCardUid()` or `updateLastReadCounter()` unless `$sdmResult['verified'] === true`.

### C2. Member records can be enumerated and scraped

`includes/members.php:88`, `user_data.php`, `verify.php`

Member numbers are short, sequential integers (for example `130`). Combined with C1, one loop over `member_id=1..N&card_uid=x` downloads every member's full record. That includes the real `card_uid`, which is then enough on its own to use the card-UID lookup. Even without C1, the unverified view confirms which numbers are valid members and whether each membership is valid.

**Fix:** fix C1 first. Then add rate limiting (see M4). Accept that the unverified view reveals membership status, or require a card tap for any lookup.

---

## High

### H1. Personal data workbook sits in the project folder

`example_data/00PTR_SYSTEM_TEST.xlsm`

The workbook contains names, surnames, addresses, phone numbers, e-mails and remarks for members. The code only needs this file on the computer running the import tool. If the project folder is uploaded to the host, zipped, shared or committed to git, the file goes with it. On the host it would be downloadable by anyone who guesses the path. This is a RODO/GDPR breach risk.

**Fix:**
- Keep the file out of the project folder, or replace it with a fully anonymised sample with the same columns.
- Never upload `example_data/` to the host. Add a `.gitignore` entry if the project is ever put under git.

### H2. Secrets stored in plain text in `config.php`

`config.php:5–13`

The file holds the database password, the import API password and the NTAG424 master key. Its header comment says it is a template and gitignored, but the folder is not a git repository and the real values are in it.

- On the host, PHP files are executed rather than served, so `config.php` is not readable over HTTP. That is acceptable.
- The risk is copies: backups, zips, screenshots, sharing the folder.

**Fix:**
- Keep a `config.example.php` with placeholders for sharing, and keep the real `config.php` only on the host and one trusted machine.
- Rotate the database password and `$api_key` if the folder has ever been shared.
- Note that the NTAG master key cannot be rotated without reprogramming every card, so guard it closely.
- `$ntag424_meta_read_key` is all zeros. Set a real key before enabling encrypted SDM data.

### H3. Test page and helper files would be public if uploaded

`index.html`, `create_members_table.sql`, `seed_test_members.sql`, `example_data/`

- `index.html` is a one-click member lookup tool. Its preset cases include the "verified" view, which makes C1/C2 trivial for anyone who opens the site root.
- The SQL files would be served as plain text. That is low impact on its own, but it reveals the schema.

**Fix:**
- Do not upload `index.html`, the `.sql` files, `example_data/` or `import_tool.html` to production. `import_tool.html` is meant to run locally.
- If test files must be on the host, protect them with `.htaccess` basic auth. In any case, add to the site root:

  ```apache
  Options -Indexes
  <FilesMatch "\.(sql|md|xlsm|xlsx)$">
      Require all denied
  </FilesMatch>
  ```

  and an `includes/.htaccess` with `Require all denied`.

---

## Medium

### M1. Import password remembered in `localStorage` of a `file://` page

`import_tool.html:359`, `import_tool.html:374`

When "Zapamiętaj hasło" (remember password) is ticked, the API key is stored in plain text in `localStorage`.

- In Chrome and Edge, all local `file://` pages share one storage origin. Any other HTML file opened from disk on that computer can read the key.
- Anyone with access to the Windows user account can read it too.

**Fix:**
- Tell users to tick "remember" only on a personal, trusted computer.
- Better: remove the option, or store it in `sessionStorage` so it is forgotten when the browser closes.

### M2. SheetJS 0.18.5 from a CDN: known CVEs, no integrity check

`import_tool.html:305`

- SheetJS CE 0.18.5 has published vulnerabilities:
  - prototype pollution when reading crafted files (CVE-2023-30533, fixed in 0.19.3)
  - ReDoS (CVE-2024-22363, fixed in 0.20.2)

  The practical risk is low, since users open their own workbook, but a malicious workbook could exploit it.
- The script is loaded without a Subresource Integrity (`integrity=`) hash. If the CDN copy were ever tampered with, the attacker's script would see both the import password and the full workbook, including personal data.

**Fix:** use SheetJS ≥ 0.20.2 from `cdn.sheetjs.com` with an `integrity` hash, or embed the library in the HTML file. Embedding keeps the tool single-file and makes it work offline for parsing.

### M3. Import can overwrite or clear data for all members, with no backup or audit trail

`import_api.php` (`importRun`)

- Anyone with the API key can rewrite `license_level`, `membership_type` and `membership_expiration_date` for every member.
- An empty cell clears the stored value, so a wrong or old workbook can mass-expire memberships.
- The preview step helps, but there is no record of who changed what, and no easy way back.

**Fix:**
- Before each non-dry-run import, write the affected rows' old values to a `member_import_log` table: timestamp, IP, member id, field, old value, new value.
- Optionally refuse imports that would clear or shorten the expiration date for more than N % of members without an explicit override.

### M4. No rate limiting on the public lookup endpoints

`verify.php`, `user_data.php`

There is no throttling, so enumeration (C2) runs at full speed. Each request also opens one or two MySQL connections, which on free hosting can exhaust the connection limit (easy denial of service).

**Fix:**
- Add a simple per-IP limit, for example 30 lookups per minute stored in a small DB table or in APCu if available.
- Reuse one DB connection per request instead of opening one per query.

---

## Low

### L1. Import lockout is per-IP in a shared temp directory

`import_api.php:56–57`

- The failure counter lives in `sys_get_temp_dir()`. On shared hosting that directory may be shared with other sites or cleared at any time.
- If `REMOTE_ADDR` is a proxy address, one attacker's 5 bad attempts lock out every user for 15 minutes.
- Brute force itself is infeasible: the key is 256 bits of randomness. So this mainly matters as a nuisance lockout.

**Fix:** keep the counter in the database or in a file under a protected folder of the site. Optionally lock per IP **and** add a small global delay instead of a hard lockout.

### L2. CORS reflects any origin with credentials

`import_api.php:44–46`

Any website can call the API from a visitor's browser and read the response, with cookies attached. Authorisation is the API key in the request body, and the only cookie is the host's anti-bot cookie, so no action is possible without the key. This is acceptable, but broader than needed.

**Fix:** allow only `Origin: null` (the local tool) and the site's own origin, and drop `Allow-Credentials` if the host's anti-bot check turns out not to need the cookie.

### L3. Missing security and cache headers

`verify.php`, `user_data.php`

- There is no `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` or `X-Frame-Options` / `frame-ancestors`.
- Verified member responses carry no `Cache-Control: no-store`, so browsers and proxies may cache personal data.
- URLs carry the member number and card UID and may end up in browser history and server logs.

**Fix:**
- On `verify.php`, send:
  ```
  Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Cache-Control: no-store
  ```
- On `user_data.php`, send `nosniff` and `no-store`.
- Enable HSTS if the host supports it.

### L4. Non-numeric member numbers match member `0`

`includes/members.php:110–111`

`CAST('abc' AS UNSIGNED)` is `0`, so `member_id=abc` matches a stored member `0` / `0000000000` if one exists.

**Fix:** only add the `CAST` condition when the input is all digits. Also reject member numbers longer than about 20 characters.

### L5. Verified response exposes more fields than needed

`includes/members.php:193` (`formatVerifiedMember`)

The response includes the internal database `id`, the `card_uid` and the free-text `info`.

- `card_uid` is the only secret for the card-UID lookup.
- `info` may contain personal data.

**Fix (RODO data minimisation):**
- Drop `id` and `card_uid` from the public response.
- Show `info` only if it is confirmed never to hold personal data.

---

## Info

### I1. Hosting and RODO compliance

Member data (member number, class, position, validity, card UID, remarks) is processed on free InfinityFree hosting.

- Check whether a data processing agreement (umowa powierzenia przetwarzania danych) is available, and where the data is stored.
- Record this processing in the association's register of processing activities.
- Paid EU hosting would also allow direct DB access and remove the host's anti-bot check, which can interfere with `import_tool.html`.

---

## Recommended order

1. C1: require a matching `card_uid`, and stop DB writes on unverified requests.
2. H3 and H1: remove `index.html`, the SQL files, `example_data/` and `import_tool.html` from the host, and add the `.htaccess` rules. Move or anonymise the workbook.
3. H2: split out `config.example.php`, and rotate the passwords if the folder was shared.
4. M2 and M1: pin SheetJS ≥ 0.20.2 with SRI or embed it, and drop or limit password remembering.
5. M4 and M3: rate-limit the lookups, and add an import audit log.
6. Low items as time allows.
