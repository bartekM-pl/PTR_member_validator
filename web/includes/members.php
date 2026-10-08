<?php

require_once __DIR__ . '/db.php';

/**
 * Member numbers may appear in links zero-padded to 10 digits
 * (e.g. 0000000123). Stored values may be padded or unpadded.
 *
 * @param mixed $value
 * @return array{raw: string, unpadded: string, padded: string}|null
 */
function normalizeMemberNumber($value) {
    $raw = trim((string) $value);
    if ($raw === '') {
        return null;
    }

    if (!ctype_digit($raw)) {
        return array(
            'raw' => $raw,
            'unpadded' => $raw,
            'padded' => $raw,
        );
    }

    $unpadded = ltrim($raw, '0');
    if ($unpadded === '') {
        $unpadded = '0';
    }

    return array(
        'raw' => $raw,
        'unpadded' => $unpadded,
        'padded' => str_pad($unpadded, 10, '0', STR_PAD_LEFT),
    );
}

/**
 * @param array<string, mixed> $row
 * @return array<string, mixed>
 */
function enrichMemberRow($row) {
    if ($row === null) {
        return null;
    }

    $expiration = $row['membership_expiration_date'] ?? null;
    $row['membership_valid'] = false;

    if ($expiration !== null && $expiration !== '') {
        $today = new DateTimeImmutable('today');
        $expiry = DateTimeImmutable::createFromFormat('Y-m-d', $expiration);
        if ($expiry !== false) {
            $row['membership_valid'] = $expiry >= $today;
        }
    }

    return $row;
}

/**
 * @return array<string, mixed>|null
 */
function getMemberById($id) {
    $conn = getDbConnection();
    $rows = dbFetchAll(
        $conn,
        'SELECT id, member_id, card_uid, license_level, membership_expiration_date, membership_type, info, last_read_counter
         FROM members WHERE id = ? LIMIT 1',
        'i',
        array($id)
    );
    $conn->close();

    if (empty($rows)) {
        return null;
    }

    return enrichMemberRow($rows[0]);
}

/**
 * Look up a member by membership number.
 * Accepts unpadded values (123) and 10-digit zero-padded link values (0000000123).
 *
 * @return array<string, mixed>|null
 */
function getMemberByMemberNumber($memberNumber) {
    $normalized = normalizeMemberNumber($memberNumber);
    if ($normalized === null) {
        return null;
    }

    $candidates = array_values(array_unique(array(
        $normalized['raw'],
        $normalized['unpadded'],
        $normalized['padded'],
    )));

    $placeholders = implode(', ', array_fill(0, count($candidates), '?'));
    $types = str_repeat('s', count($candidates));

    $conn = getDbConnection();
    $rows = dbFetchAll(
        $conn,
        "SELECT id, member_id, card_uid, license_level, membership_expiration_date, membership_type, info, last_read_counter
         FROM members
         WHERE member_id IN ($placeholders)
            OR (
                member_id REGEXP '^[0-9]+$'
                AND CAST(member_id AS UNSIGNED) = CAST(? AS UNSIGNED)
            )
         LIMIT 1",
        $types . 's',
        array_merge($candidates, array($normalized['unpadded']))
    );
    $conn->close();

    if (empty($rows)) {
        return null;
    }

    return enrichMemberRow($rows[0]);
}

/**
 * @deprecated Use getMemberByMemberNumber()
 * @return array<string, mixed>|null
 */
function getMemberByUniqueId($uniqueId) {
    return getMemberByMemberNumber($uniqueId);
}

/**
 * @return array<string, mixed>|null
 */
function getMemberByCardUid($cardUid) {
    $conn = getDbConnection();
    $rows = dbFetchAll(
        $conn,
        'SELECT id, member_id, card_uid, license_level, membership_expiration_date, membership_type, info, last_read_counter
         FROM members WHERE card_uid = ? LIMIT 1',
        's',
        array($cardUid)
    );
    $conn->close();

    if (empty($rows)) {
        return null;
    }

    return enrichMemberRow($rows[0]);
}

/**
 * @return bool
 */
function updateLastReadCounter($memberId, $counter) {
    $conn = getDbConnection();
    $affected = dbExecute(
        $conn,
        'UPDATE members SET last_read_counter = ? WHERE id = ?',
        'ii',
        array($counter, $memberId)
    );
    $conn->close();

    return $affected > 0;
}

/**
 * Bind a card UID to a member on first verified tap.
 *
 * @return bool
 */
function assignCardUid($memberId, $cardUid) {
    $conn = getDbConnection();
    $affected = dbExecute(
        $conn,
        'UPDATE members SET card_uid = ? WHERE id = ? AND (card_uid IS NULL OR card_uid = ?)',
        'sis',
        array($cardUid, $memberId, $cardUid)
    );
    $conn->close();

    return $affected > 0;
}

/**
 * @param array<string, mixed> $member
 * @return array<string, mixed>
 */
function formatVerifiedMember($member) {
    return array(
        'id' => (int) $member['id'],
        'member_id' => $member['member_id'],
        'unique_id' => $member['member_id'],
        'card_uid' => $member['card_uid'],
        'license_level' => $member['license_level'],
        'membership_type' => $member['membership_type'],
        'membership_expiration_date' => $member['membership_expiration_date'],
        'membership_valid' => (bool) $member['membership_valid'],
        'info' => $member['info'],
    );
}

/**
 * @param array<string, mixed> $member
 * @return array<string, mixed>
 */
function formatUnverifiedMember($member) {
    return array(
        'license_level' => $member['license_level'],
        'membership_valid' => (bool) $member['membership_valid'],
    );
}
