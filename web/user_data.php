<?php

require_once __DIR__ . '/includes/membership_service.php';

/**
 * Send a JSON response and stop.
 *
 * The body is JSON, never HTML: nosniff stops browsers from rendering it as a
 * page, and the JSON_HEX_* flags escape < > & ' " as \u00XX, so member data
 * (e.g. the free-text info field) cannot form markup even if it is misread.
 *
 * @param int $status
 * @param array<string, mixed> $data
 * @return never
 */
function userDataRespond($status, $data) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    // nosemgrep: JSON response with nosniff and HTML-significant characters escaped; htmlentities() would corrupt the JSON.
    echo json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    userDataRespond(405, array('error' => 'Method not allowed'));
}

$hasMemberNumber = !empty($_GET['unique_id']) || !empty($_GET['member_id']) || !empty($_GET['card_uid']);

if (!$hasMemberNumber) {
    userDataRespond(400, array('error' => 'Missing lookup parameter: member_id, unique_id (member number), or card_uid'));
}

try {
    $result = lookupMembership($_GET);
} catch (Throwable $exception) {
    error_log('Membership lookup failed: ' . $exception);
    userDataRespond(500, array('error' => 'Internal server error'));
}

if (!$result['found']) {
    userDataRespond($result['http_status'], array('error' => 'Member not found'));
}

userDataRespond($result['http_status'], array(
    'verified' => $result['verified'],
    'member' => $result['member'],
));
