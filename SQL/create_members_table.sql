-- Members table used by includes/members.php.

CREATE TABLE IF NOT EXISTS members (
    id                         INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    -- Membership number; links may carry it zero-padded to 10 digits.
    member_id                  VARCHAR(32)   NOT NULL,
    -- NTAG424 UID, 7 bytes as 14 uppercase hex chars. NULL until a card is bound.
    card_uid                   VARCHAR(14)   NULL DEFAULT NULL,
    license_level              VARCHAR(32)   NULL DEFAULT NULL,
    -- Valid through this date (inclusive).
    membership_expiration_date DATE          NULL DEFAULT NULL,
    membership_type            VARCHAR(64)   NULL DEFAULT NULL,
    info                       TEXT          NULL,
    -- Last accepted SDM read counter (24-bit), for replay protection.
    last_read_counter          INT UNSIGNED  NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_members_member_id (member_id),
    UNIQUE KEY uq_members_card_uid (card_uid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
