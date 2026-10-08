<?php
// Copy this file to config.php and fill in real values.
// config.php is gitignored.

// Password for the member import tool (import_api.php). Keep it secret.
// At least 32 characters, otherwise the import API stays disabled.
$api_key = 'your_api_key_here';

$sql_address = 'localhost';
$sql_login = 'user';
$sql_pass = 'password';
$sql_dbname = 'members';

// NTAG424 SDM File Read Key (App Key used for CMAC). 32 hex chars = 16 bytes.
$ntag424_master_key = '00000000000000000000000000000000';

// NTAG424 SDM Meta Read Key (for encrypted PICC data / e= parameter). Not UID-diversified.
$ntag424_meta_read_key = '00000000000000000000000000000000';

// When true, derive per-card SDM File Read Key from master key + card UID (AN10922).
$ntag424_use_key_diversification = true;

// NDEF URI template programmed on the tag (zeros = SDM mirror placeholders).
// {unique_id} is replaced with the member unique_id when programming each card.
$ntag424_sdm_url_template = 'https://example.com/verify.php?unique_id={unique_id}&uid=0000000000000000&ctr=000000&cmac=0000000000000000';

// Byte offsets in the NDEF DynamicFileData for CMAC input (decimal, per TagXplorer / AN12196).
$ntag424_sdm_mac_input_offset = 44;
$ntag424_sdm_mac_offset = 61;

// Site base URL for verify page (used when reconstructing NDEF data for CMAC).
$site_base_url = 'https://example.com';
