# PTR Member Validator

A small PHP + MySQL web app for checking PTR memberships. A member's NFC card (NXP NTAG 424 DNA) carries a link to `verify.php`. Tapping the card opens a page that shows whether the membership is valid. A local, browser-only import tool syncs member data from the PTR Excel workbook to the database.

> **Status:** NTAG424 SDM/CMAC verification (`includes/ntag424_sdm.php`) is implemented but **disabled**. Right now a request counts as "verified" whenever a `card_uid` parameter is present. Read [`web/AUDIT.md`](web/AUDIT.md) before deploying to production.

## Repository layout

```
SQL/
  create_members_table.sql   Schema for the `members` table
  seed_test_members.sql      Test rows (info starts with 'TEST'), with a cleanup query
example_data/
  00PTR_SYSTEM_TEST.xlsm     Sample PTR workbook used by the import tool
web/                         Document root for the host
  verify.php                 Public HTML verification page (target of the card link)
  user_data.php              Public JSON lookup API
  import_api.php             Authenticated member import API (POST, JSON)
  import_tool.html           Local import tool, opened from disk (UI in Polish)
  index.html                 Manual test page for user_data.php / verify.php
  config.php                 DB credentials, import API key, NTAG424 keys
  includes/
    db.php                   mysqli connection and prepared-statement helpers
    members.php              Member queries, member-number normalisation, output formatting
    membership_service.php   Lookup flow shared by verify.php and user_data.php
    ntag424_sdm.php          NTAG424 SDM: AES-CMAC, key diversification, session keys (AN12196)
  assets/css/verify.css      Styles for verify.php and index.html
  AUDIT.md                   Security audit (2026-09-30) with findings and fix order
```

## Requirements

- PHP 7.4+ with the `mysqli`, `openssl` and `mbstring` extensions
- MySQL / MariaDB (InnoDB, `utf8mb4`)
- A modern browser for `import_tool.html` (it loads SheetJS 0.20.3 from cdn.sheetjs.com, pinned with an SRI hash)

## Setup

1. Create the database table:
   ```sh
   mysql -u <user> -p <dbname> < SQL/create_members_table.sql
   ```
2. (Optional) Load test members:
   ```sh
   mysql -u <user> -p <dbname> < SQL/seed_test_members.sql
   ```
   Remove them later with `DELETE FROM members WHERE info LIKE 'TEST%';`.
3. Copy `web/config.example.php` to `web/config.php` (gitignored) and fill it in:

   | Variable | Purpose |
   |---|---|
   | `$sql_address`, `$sql_login`, `$sql_pass`, `$sql_dbname` | MySQL connection |
   | `$api_key` | Password for `import_api.php`. At least 32 characters, otherwise import is disabled |
   | `$ntag424_master_key` | SDM File Read Key (32 hex chars) |
   | `$ntag424_meta_read_key` | SDM Meta Read Key for encrypted PICC data (`e=` parameter) |
   | `$ntag424_use_key_diversification` | Derive a per-card key from the master key and the card UID (AN10922) |
   | `$ntag424_sdm_url_template` | NDEF URL programmed on the cards. `{unique_id}` is the member number |
   | `$ntag424_sdm_mac_input_offset`, `$ntag424_sdm_mac_offset` | Byte offsets used for CMAC input |
   | `$site_base_url` | Public base URL of the site |

4. Upload the **contents of `web/`** to the host. Do not upload `index.html`, `import_tool.html`, the `SQL/` files or `example_data/` to production (see AUDIT.md, H1 and H3).

## Data model

One table, `members`:

| Column | Notes |
|---|---|
| `member_id` | Membership number (unique). Links may carry it zero-padded to 10 digits |
| `card_uid` | NTAG424 UID, 14 uppercase hex chars (unique). `NULL` until a card is bound |
| `license_level` | Licence class |
| `membership_type` | Position / membership type |
| `membership_expiration_date` | Valid **through** this date, inclusive. `NULL` means expired |
| `info` | Free text. Never changed by the import |
| `last_read_counter` | Last accepted SDM read counter, for replay protection |

Member-number lookup accepts `123`, `0000000123` and any stored padding.

## Endpoints

### `verify.php` (HTML)

The page members and inspectors see after a card tap.

```
verify.php?unique_id=0000000123
verify.php?member_id=123&card_uid=04AABBCCDDEEFF
verify.php?card_uid=04AABBCCDDEEFF
```

- **Unverified link** (no `card_uid`): shows only the licence level and Valid/Expired status.
- **Verified card tap**: shows the member number, type, licence level, expiration date, status and info.
- Shows "Not Found" if no member matches.

### `user_data.php` (JSON)

`GET` with the same parameters as `verify.php` (`member_id`, `unique_id` or `card_uid`).

| Status | Body |
|---|---|
| 200 | `{"verified": bool, "member": {...}}` |
| 400 | No lookup parameter given |
| 404 | `{"error": "Member not found"}` |
| 405 | Not a GET request |
| 500 | Internal error (details go to the PHP error log) |

An unverified `member` has only `license_level` and `membership_valid`. A verified one also has `id`, `member_id`, `card_uid`, `membership_type`, `membership_expiration_date` and `info`.

### `import_api.php` (JSON)

`POST` with a JSON body sent as `text/plain`, so a page opened from `file://` can call it without a CORS preflight:

```json
{
  "api_key": "...",
  "dry_run": true,
  "rows": [
    {"sheet_row": 2, "member_id": "123", "license_level": "A",
     "membership_type": "Full", "membership_expiration_date": "2027-05-01",
     "card_uid": "04AABBCCDDEEFF"}
  ]
}
```

- Inserts new members and updates `license_level`, `membership_type` and `membership_expiration_date` for existing ones. Members missing from the upload are left as they are. `info` is never touched.
- An empty `card_uid` keeps the stored UID. A new UID resets `last_read_counter`. A UID bound to another member is rejected for that row.
- `dry_run: true` returns the planned changes per row without writing anything. Real runs write in one transaction.
- Limits: 5000 rows, 2 MB body. After 5 wrong keys the IP is locked out for 15 minutes.
- Response: `{"dry_run", "summary": {"insert","update","unchanged","error"}, "untouched_in_db", "rows": [...]}`.

## Import tool

`web/import_tool.html` runs locally: open it from disk in a browser.

1. Choose the PTR workbook (`.xlsm` / `.xlsx`). The tool finds the sheet that has a `Nr legitymacji` column.
2. Enter the import password (`$api_key`) and, if needed, the server URL.
3. Run the preview (dry run), review the changes, then save.

The workbook is parsed in the browser. Only these columns are read, and nothing else (names, addresses, phone numbers, e-mails, remarks) leaves the computer:

| Workbook column | Field |
|---|---|
| Nr legitymacji | `member_id` |
| Klasa | `license_level` |
| Stanowisko w PTR | `membership_type` |
| Ostatnia składka | `membership_expiration_date` = last fee date + 365 days |
| UID / UID karty / Nr karty / … (optional) | `card_uid` |

## Testing

There is no automated test suite. `web/index.html` is a manual test page. It builds requests to `user_data.php` / `verify.php` and runs a set of preset cases against `user_data.php` (it defaults to the seeded member `123` / `04AABBCCDDEEFF`). Serve `web/` locally, for example:

```sh
cd web
php -S localhost:8000
```

Then open `http://localhost:8000/index.html`.

## NTAG424 SDM

`includes/ntag424_sdm.php` implements NXP AN12196 SDM verification: AES-CMAC (NIST SP 800-38B), optional AN10922 per-card key diversification, SV2 session MAC key derivation, PICC data decryption for the `e=` parameter, and truncated-CMAC comparison over the NDEF data rebuilt from `$ntag424_sdm_url_template`. `ntag424CheckReplayAndBinding()` rejects counters that are not higher than the stored one and UIDs that differ from the bound card.

This path is not used yet: `membership_service.php` has `ntag424CheckReplayAndBinding()` commented out. Review and test it before enabling it.

## Security

See [`web/AUDIT.md`](web/AUDIT.md) for the full audit and the recommended fix order. The main points:

- A request with any `card_uid` value currently returns full member details and can write to the database (C1).
- `config.php` contains real secrets. Keep it out of shared copies and rotate the credentials if it has been exposed (H2).
- `example_data/` may contain personal data (RODO/GDPR). Never upload it to the host (H1).
