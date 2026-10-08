<?php

/**
 * Member import API, used by the local tool import_tool.html.
 *
 * The tool parses the PTR workbook on the user's computer and sends only
 * fields that exist in the members table:
 *   member_id, license_level, membership_type, membership_expiration_date, card_uid
 * Anything else in a row is ignored. info is never modified, and members
 * missing from the upload are left untouched.
 *
 * card_uid is optional: an empty value leaves the stored UID as it is (so an
 * import never unbinds a card). A new UID resets last_read_counter, since a
 * replacement card starts counting from zero. A UID already bound to another
 * member is rejected for that row.
 *
 * Request: POST, body is JSON sent as text/plain (a "simple" CORS request,
 * so no preflight is needed from a file:// page):
 *   {"api_key": "...", "dry_run": true, "rows": [{...}, ...]}
 *
 * Protection: $api_key from config.php (min. 32 chars), constant-time compare,
 * per-IP lockout after repeated wrong keys, POST only, row count limit.
 */

require_once __DIR__ . '/includes/db.php';

const IMPORT_MAX_ROWS = 5000;
const IMPORT_MAX_BODY_BYTES = 2000000;
const IMPORT_MIN_KEY_LENGTH = 32;
const IMPORT_MAX_FAILURES = 5;
const IMPORT_LOCKOUT_SECONDS = 900;
const IMPORT_FIELDS = array('license_level', 'membership_type', 'membership_expiration_date');

/**
 * Row error with extra data for the tool to show (e.g. the conflicting member).
 */
class ImportRowException extends InvalidArgumentException {
    /** @var array<string, mixed> */
    public $detail;

    /**
     * @param string $message
     * @param array<string, mixed> $detail
     */
    public function __construct($message, $detail) {
        parent::__construct($message);
        $this->detail = $detail;
    }
}

/**
 * @param int $status
 * @param array<string, mixed> $data
 */
function importRespond($status, $data) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data);
    exit;
}

function importSendCorsHeaders() {
    // Auth is the API key in the body, not cookies, so any origin may call.
    // A page opened from disk sends "Origin: null".
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Vary: Origin');
}

/**
 * @return string
 */
function importThrottleFile() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return sys_get_temp_dir() . '/ptr_import_throttle_' . hash('sha256', $ip) . '.json';
}

/**
 * @return array{failures: int, locked_until: int}
 */
function importThrottleState() {
    $file = importThrottleFile();
    $state = is_file($file) ? json_decode((string) @file_get_contents($file), true) : null;
    if (!is_array($state)) {
        $state = array();
    }

    return array(
        'failures' => (int) ($state['failures'] ?? 0),
        'locked_until' => (int) ($state['locked_until'] ?? 0),
    );
}

function importRecordFailure() {
    $state = importThrottleState();
    $state['failures']++;
    if ($state['failures'] >= IMPORT_MAX_FAILURES) {
        $state['locked_until'] = time() + IMPORT_LOCKOUT_SECONDS;
        $state['failures'] = 0;
    }
    @file_put_contents(importThrottleFile(), json_encode($state), LOCK_EX);
}

function importClearFailures() {
    $file = importThrottleFile();
    if (is_file($file)) {
        @unlink($file);
    }
}

/**
 * @param string $memberId
 * @return string
 */
function importMemberKey($memberId) {
    if (ctype_digit($memberId)) {
        $unpadded = ltrim($memberId, '0');
        return $unpadded === '' ? '0' : $unpadded;
    }

    return strtoupper($memberId);
}

/**
 * @param mixed $value
 * @param int $maxLength
 * @return string|null
 */
function importOptionalString($value, $maxLength) {
    if ($value === null) {
        return null;
    }

    if (!is_scalar($value)) {
        throw new InvalidArgumentException('invalid value');
    }

    $value = trim((string) $value);
    if ($value === '') {
        return null;
    }

    if (mb_strlen($value, 'UTF-8') > $maxLength) {
        throw new InvalidArgumentException('value longer than ' . $maxLength . ' characters');
    }

    return $value;
}

/**
 * Validate one incoming row. Unknown keys are ignored on purpose.
 *
 * @param mixed $row
 * @return array{member_id: string, license_level: string|null, membership_type: string|null, membership_expiration_date: string|null}
 */
function importCleanRow($row) {
    if (!is_array($row)) {
        throw new InvalidArgumentException('row is not an object');
    }

    $memberId = importOptionalString($row['member_id'] ?? null, 32);
    if ($memberId === null || !preg_match('/^[0-9A-Za-z_-]{1,32}$/', $memberId)) {
        throw new InvalidArgumentException('invalid member number');
    }

    $expiration = importOptionalString($row['membership_expiration_date'] ?? null, 10);
    if ($expiration !== null) {
        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $expiration);
        if ($date === false || $date->format('Y-m-d') !== $expiration) {
            throw new InvalidArgumentException('invalid expiration date');
        }
    }

    return array(
        'member_id' => $memberId,
        'license_level' => importOptionalString($row['license_level'] ?? null, 32),
        'membership_type' => importOptionalString($row['membership_type'] ?? null, 64),
        'membership_expiration_date' => $expiration,
        'card_uid' => importCardUid($row['card_uid'] ?? null),
    );
}

/**
 * NTAG424 UID: 7 bytes as 14 hex chars. Spaces, colons and dashes are
 * accepted as separators ("04:AA:BB:..."). Empty means "do not change".
 *
 * @param mixed $value
 * @return string|null
 */
function importCardUid($value) {
    $uid = importOptionalString($value, 32);
    if ($uid === null) {
        return null;
    }

    $uid = strtoupper(preg_replace('/[\s:-]/', '', $uid));
    if (!preg_match('/^[0-9A-F]{14}$/', $uid)) {
        throw new InvalidArgumentException('invalid card uid');
    }

    return $uid;
}

/**
 * @param array<string, mixed> $payload
 * @return array<string, mixed>
 */
function importRun($payload) {
    $dryRun = !empty($payload['dry_run']);
    $rows = $payload['rows'] ?? null;
    if (!is_array($rows)) {
        throw new InvalidArgumentException('rows must be an array');
    }
    if (count($rows) > IMPORT_MAX_ROWS) {
        throw new InvalidArgumentException('too many rows (max ' . IMPORT_MAX_ROWS . ')');
    }

    $conn = getDbConnection();

    $existing = array();
    $uidOwners = array();
    foreach (dbFetchAll($conn, 'SELECT id, member_id, license_level, membership_type, membership_expiration_date, card_uid FROM members') as $member) {
        $key = importMemberKey((string) $member['member_id']);
        if (!isset($existing[$key])) {
            $existing[$key] = $member;
        }
        if ($member['card_uid'] !== null && $member['card_uid'] !== '') {
            $uidOwners[strtoupper($member['card_uid'])] = array('key' => $key, 'member_id' => $member['member_id']);
        }
    }

    $results = array();
    $summary = array('insert' => 0, 'update' => 0, 'unchanged' => 0, 'error' => 0);
    $seen = array();
    $seenUids = array();
    $writes = array();

    foreach (array_values($rows) as $index => $row) {
        $sheetRow = is_array($row) && isset($row['sheet_row']) ? (int) $row['sheet_row'] : $index + 1;
        $result = array('sheet_row' => $sheetRow);

        try {
            $clean = importCleanRow($row);
            $key = importMemberKey($clean['member_id']);
            if (isset($seen[$key])) {
                throw new InvalidArgumentException('duplicate member number (also in row ' . $seen[$key] . ')');
            }
            $uid = $clean['card_uid'];
            if ($uid !== null) {
                if (isset($seenUids[$uid])) {
                    throw new ImportRowException('duplicate card uid', array('row' => $seenUids[$uid]));
                }
                if (isset($uidOwners[$uid]) && $uidOwners[$uid]['key'] !== $key) {
                    throw new ImportRowException('card uid in use', array('member_id' => $uidOwners[$uid]['member_id']));
                }
            }

            $seen[$key] = $sheetRow;
            if ($uid !== null) {
                $seenUids[$uid] = $sheetRow;
            }
            $result['member_id'] = $clean['member_id'];

            if (!isset($existing[$key])) {
                $result['action'] = 'insert';
                $writes[] = array('insert', null, $clean, false);
            } else {
                $changes = array();
                foreach (IMPORT_FIELDS as $field) {
                    $old = $existing[$key][$field];
                    $old = ($old === null || $old === '') ? null : (string) $old;
                    if ($old !== $clean[$field]) {
                        $changes[] = array('field' => $field, 'from' => $old, 'to' => $clean[$field]);
                    }
                }

                $oldUid = $existing[$key]['card_uid'];
                $oldUid = ($oldUid === null || $oldUid === '') ? null : strtoupper($oldUid);
                $uidChanged = $uid !== null && $uid !== $oldUid;
                if ($uidChanged) {
                    $changes[] = array('field' => 'card_uid', 'from' => $oldUid, 'to' => $uid);
                }

                $result['action'] = empty($changes) ? 'unchanged' : 'update';
                $result['changes'] = $changes;
                if (!empty($changes)) {
                    $writes[] = array('update', (int) $existing[$key]['id'], $clean, $uidChanged);
                }
            }
        } catch (InvalidArgumentException $exception) {
            $result['action'] = 'error';
            $result['error'] = $exception->getMessage();
            if ($exception instanceof ImportRowException) {
                $result['error_detail'] = $exception->detail;
            }
        }

        $summary[$result['action']]++;
        $results[] = $result;
    }

    if (!$dryRun && !empty($writes)) {
        $conn->begin_transaction();
        try {
            foreach ($writes as $write) {
                list($type, $id, $clean, $uidChanged) = $write;
                if ($type === 'insert') {
                    dbExecute(
                        $conn,
                        'INSERT INTO members (member_id, license_level, membership_type, membership_expiration_date, card_uid) VALUES (?, ?, ?, ?, ?)',
                        'sssss',
                        array($clean['member_id'], $clean['license_level'], $clean['membership_type'], $clean['membership_expiration_date'], $clean['card_uid'])
                    );
                } elseif ($uidChanged) {
                    dbExecute(
                        $conn,
                        'UPDATE members SET license_level = ?, membership_type = ?, membership_expiration_date = ?, card_uid = ?, last_read_counter = NULL WHERE id = ?',
                        'ssssi',
                        array($clean['license_level'], $clean['membership_type'], $clean['membership_expiration_date'], $clean['card_uid'], $id)
                    );
                } else {
                    dbExecute(
                        $conn,
                        'UPDATE members SET license_level = ?, membership_type = ?, membership_expiration_date = ? WHERE id = ?',
                        'sssi',
                        array($clean['license_level'], $clean['membership_type'], $clean['membership_expiration_date'], $id)
                    );
                }
            }
            $conn->commit();
        } catch (Throwable $exception) {
            $conn->rollback();
            $conn->close();
            throw $exception;
        }
    }

    $conn->close();

    return array(
        'dry_run' => $dryRun,
        'summary' => $summary,
        'untouched_in_db' => count(array_diff_key($existing, $seen)),
        'rows' => $results,
    );
}

importSendCorsHeaders();

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    importRespond(405, array('error' => 'method_not_allowed'));
}

// $api_key comes from config.php (via db.php); read it once so a missing value disables import.
$importKey = isset($api_key) ? (string) $api_key : '';

if (strlen($importKey) < IMPORT_MIN_KEY_LENGTH || $importKey === 'your_api_key_here') {
    importRespond(503, array('error' => 'import_disabled'));
}

$throttle = importThrottleState();
if ($throttle['locked_until'] > time()) {
    importRespond(429, array('error' => 'locked', 'retry_after' => $throttle['locked_until'] - time()));
}

$body = (string) file_get_contents('php://input', false, null, 0, IMPORT_MAX_BODY_BYTES + 1);
if (strlen($body) > IMPORT_MAX_BODY_BYTES) {
    importRespond(413, array('error' => 'too_large'));
}

$payload = json_decode($body, true);
if (!is_array($payload)) {
    importRespond(400, array('error' => 'invalid_json'));
}

if (!is_string($payload['api_key'] ?? null) || !hash_equals($importKey, $payload['api_key'])) {
    importRecordFailure();
    sleep(1);
    importRespond(403, array('error' => 'invalid_key'));
}

importClearFailures();

try {
    importRespond(200, importRun($payload));
} catch (InvalidArgumentException $exception) {
    importRespond(400, array('error' => 'invalid_request', 'message' => $exception->getMessage()));
} catch (Throwable $exception) {
    error_log('Member import failed: ' . $exception);
    importRespond(500, array('error' => 'server_error'));
}
