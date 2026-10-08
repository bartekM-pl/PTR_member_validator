-- Test members for the validator (matches the defaults in index.html:
-- member number 123, card UID 04AABBCCDDEEFF).
-- All rows are tagged with info starting 'TEST' so they can be removed later.
-- Dates are relative to today so valid/expired status stays correct.

INSERT INTO members
    (member_id, card_uid, license_level, membership_expiration_date, membership_type, info, last_read_counter)
VALUES
    -- Valid member with a bound card (default test member)
    ('123',        '04AABBCCDDEEFF', 'A', CURDATE() + INTERVAL 1 YEAR,  'Full',    'TEST: valid, card bound',            NULL),
    -- Valid member, no card bound yet
    ('124',        NULL,             'B', CURDATE() + INTERVAL 6 MONTH, 'Full',    'TEST: valid, no card',               NULL),
    -- Expired member with a card
    ('125',        '04112233445566', 'A', CURDATE() - INTERVAL 1 MONTH, 'Full',    'TEST: expired',                      NULL),
    -- Expires today (should still be valid)
    ('126',        NULL,             'C', CURDATE(),                    'Junior',  'TEST: expires today',                NULL),
    -- Stored zero-padded, to test padded/unpadded lookup
    ('0000000127', NULL,             'B', CURDATE() + INTERVAL 1 YEAR,  'Student', 'TEST: stored zero-padded',           NULL),
    -- No expiration date (should show Expired)
    ('128',        NULL,             NULL, NULL,                        NULL,      'TEST: no expiration date\nMultiline info', NULL);

-- Cleanup:
-- DELETE FROM members WHERE info LIKE 'TEST%';
