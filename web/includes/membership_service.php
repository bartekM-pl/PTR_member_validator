<?php

require_once __DIR__ . '/members.php';
require_once __DIR__ . '/ntag424_sdm.php';

/**
 * Resolve member number from request params.
 * Accepts unique_id (legacy URL param) or member_id.
 * Values may be zero-padded to 10 digits.
 *
 * @param array<string, mixed> $params
 * @return string|null
 */
function extractMemberNumberParam($params) {
    if (!empty($params['member_id'])) {
        return trim((string) $params['member_id']);
    }

    if (!empty($params['unique_id'])) {
        return trim((string) $params['unique_id']);
    }

    return null;
}

function extractCUIDParam($params) {
    if (!empty($params['card_uid'])) {
        return trim((string) $params['card_uid']);
    }

    return null;
}

/**
 * @param array<string, mixed> $params
 * @return array<string, mixed>
 */
function lookupMembership($params) {
    $member = null;
    $memberNumber = extractMemberNumberParam($params);
	$cardUID = extractCUIDParam($params);

    if ($memberNumber !== null) {
        $member = getMemberByMemberNumber($memberNumber);
    } elseif ($cardUID !== null) {
        $member = getMemberByCardUid($cardUID);
    }

    if ($member === null) {
        return array(
            'found' => false,
            'verified' => false,
            'member' => null,
            'http_status' => 404,
        );
    }

    // Ensure SDM URL template substitution uses the stored member number.
    if ($memberNumber !== null) {
        $params['member_id'] = $member['member_id'];
        $params['card_uid'] = $member['card_uid'];
    }

    $sdmResult = ntag424VerifySdm($params, $member);
    $verified = ($cardUID !== null); //ntag424CheckReplayAndBinding($member, $sdmResult);

    if ($verified) {
        if (empty($member['card_uid']) && !empty($sdmResult['card_uid'])) {
            assignCardUid((int) $member['id'], $sdmResult['card_uid']);
            $member['card_uid'] = $sdmResult['card_uid'];
        }

        updateLastReadCounter((int) $member['id'], (int) $sdmResult['counter']);
        $member = getMemberById((int) $member['id']);

        return array(
            'found' => true,
            'verified' => true,
            'member' => formatVerifiedMember($member),
            'http_status' => 200,
        );
    }

    return array(
        'found' => true,
        'verified' => false,
        'member' => formatUnverifiedMember($member),
        'http_status' => 200,
    );
}
