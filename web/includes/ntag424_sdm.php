<?php

/**
 * NTAG424 DNA Secure Dynamic Messaging (SDM) verification.
 * Implements NXP AN12196 session key generation and CMAC validation.
 */

const NTAG424_CMAC_Rb = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87";

/**
 * @param string $hex
 * @return string|null
 */
function ntag424HexToBin($hex) {
    $hex = preg_replace('/[^0-9a-fA-F]/', '', $hex);
    if ($hex === '' || (strlen($hex) % 2) !== 0) {
        return null;
    }

    return hex2bin($hex);
}

/**
 * @param string $data
 * @return string
 */
function ntag424BinToHex($data) {
    return strtoupper(bin2hex($data));
}

/**
 * @param string $block
 * @param string $rb
 * @return string
 */
function ntag424CmacDouble($block, $rb) {
    $leftShift = ntag424LeftShift128($block);
    if ((ord($block[0]) & 0x80) !== 0) {
        $leftShift = $leftShift ^ $rb;
    }

    return $leftShift;
}

/**
 * @param string $block
 * @return string
 */
function ntag424LeftShift128($block) {
    $output = '';
    $carry = 0;
    for ($i = 15; $i >= 0; $i--) {
        $byte = ord($block[$i]);
        $newByte = (($byte << 1) & 0xFF) | $carry;
        $carry = ($byte & 0x80) !== 0 ? 1 : 0;
        $output = chr($newByte) . $output;
    }

    return $output;
}

/**
 * AES-CMAC per NIST SP 800-38B.
 *
 * @param string $key 16 bytes
 * @param string $message
 * @return string 16 bytes
 */
function ntag424AesCmac($key, $message) {
    $L = openssl_encrypt(str_repeat("\x00", 16), 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
    if ($L === false) {
        throw new RuntimeException('Failed to derive CMAC subkey L.');
    }

    $K1 = ntag424CmacDouble($L, NTAG424_CMAC_Rb);
    $K2 = ntag424CmacDouble($K1, NTAG424_CMAC_Rb);

    $messageLength = strlen($message);
    $blockCount = max(1, (int) ceil($messageLength / 16));
    $lastBlockComplete = ($messageLength > 0) && ($messageLength % 16 === 0);

    if ($messageLength === 0) {
        $lastBlock = $K2 ^ (str_repeat("\x00", 15) . "\x80");
    } elseif ($lastBlockComplete) {
        $lastBlock = substr($message, -16) ^ $K1;
    } else {
        $partial = substr($message, ($blockCount - 1) * 16);
        $padding = $partial . "\x80" . str_repeat("\x00", 15 - (strlen($partial) % 16));
        $lastBlock = $padding ^ $K2;
    }

    $x = str_repeat("\x00", 16);
    for ($i = 0; $i < $blockCount - 1; $i++) {
        $block = substr($message, $i * 16, 16);
        $x = openssl_encrypt($block ^ $x, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
        if ($x === false) {
            throw new RuntimeException('CMAC block encryption failed.');
        }
    }

    $x = openssl_encrypt($lastBlock ^ $x, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
    if ($x === false) {
        throw new RuntimeException('CMAC finalization failed.');
    }

    return $x;
}

/**
 * NTAG424 truncated MAC (odd-indexed bytes of full CMAC).
 *
 * @param string $key
 * @param string $message
 * @return string 8 bytes
 */
function ntag424AesCmacTruncated($key, $message) {
    $full = ntag424AesCmac($key, $message);
    $truncated = '';
    for ($i = 1; $i < 16; $i += 2) {
        $truncated .= $full[$i];
    }

    return $truncated;
}

/**
 * Derive per-card SDM File Read Key (NXP AN10922-style diversification).
 *
 * @param string $masterKey 16 bytes
 * @param string $uidBin 7 bytes
 * @return string 16 bytes
 */
function ntag424DeriveDiversifiedKey($masterKey, $uidBin) {
    $input = "\x01\x00" . $uidBin;
    $input = str_pad($input, 16, "\x00");

    return ntag424AesCmac($masterKey, $input);
}

/**
 * @param string $ctrHex 6 hex chars from URL
 * @return int|null
 */
function ntag424ParseCounter($ctrHex) {
    $ctrHex = preg_replace('/[^0-9a-fA-F]/', '', $ctrHex);
    if ($ctrHex === '' || strlen($ctrHex) > 6) {
        return null;
    }

    $ctrHex = str_pad($ctrHex, 6, '0', STR_PAD_LEFT);

    return hexdec($ctrHex);
}

/**
 * @param int $counter
 * @return string 3 bytes, LSB first
 */
function ntag424CounterToBytes($counter) {
    return chr($counter & 0xFF)
        . chr(($counter >> 8) & 0xFF)
        . chr(($counter >> 16) & 0xFF);
}

/**
 * @param string $uidBin
 * @param string $ctrBytes
 * @return string
 */
function ntag424BuildSv2($uidBin, $ctrBytes) {
    return hex2bin('3CC300010080') . $uidBin . $ctrBytes;
}

/**
 * @param string $sdmFileReadKey
 * @param string $uidBin
 * @param string $ctrBytes
 * @return string
 */
function ntag424DeriveSessionMacKey($sdmFileReadKey, $uidBin, $ctrBytes) {
    $sv2 = ntag424BuildSv2($uidBin, $ctrBytes);

    return ntag424AesCmac($sdmFileReadKey, $sv2);
}

/**
 * @param string $encryptedHex
 * @param string $metaReadKey 16 bytes
 * @return array{uid: string, counter: int, ctr_bytes: string}|null
 */
function ntag424DecryptPiccData($encryptedHex, $metaReadKey) {
    $encrypted = ntag424HexToBin($encryptedHex);
    if ($encrypted === null || strlen($encrypted) !== 16) {
        return null;
    }

    $iv = str_repeat("\x00", 16);
    $decrypted = openssl_decrypt($encrypted, 'aes-128-cbc', $metaReadKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
    if ($decrypted === false || strlen($decrypted) < 11) {
        return null;
    }

    $uidBin = substr($decrypted, 1, 7);
    $ctrBytes = substr($decrypted, 8, 3);
    $counter = ord($ctrBytes[0]) | (ord($ctrBytes[1]) << 8) | (ord($ctrBytes[2]) << 16);

    return array(
        'uid' => ntag424BinToHex($uidBin),
        'counter' => $counter,
        'ctr_bytes' => $ctrBytes,
        'uid_bin' => $uidBin,
    );
}

/**
 * @param array<string, mixed> $params
 * @return bool
 */
function ntag424HasSdmParams($params) {
    $hasPlain = !empty($params['uid']) && (!empty($params['ctr']) || !empty($params['counter']));
    $hasEncrypted = !empty($params['e']) || !empty($params['picc_data']);

    return ($hasPlain || $hasEncrypted) && (!empty($params['cmac']) || !empty($params['c']));
}

/**
 * @param string $template
 * @param string $uniqueId
 * @param string $uid
 * @param string $ctr
 * @param string $cmac
 * @return string
 */
function ntag424BuildDynamicFileData($template, $uniqueId, $uid, $ctr, $cmac) {
    $memberNumber = trim((string) $uniqueId);
    if ($memberNumber !== '' && ctype_digit($memberNumber)) {
        $unpadded = ltrim($memberNumber, '0');
        if ($unpadded === '') {
            $unpadded = '0';
        }
        $memberNumber = str_pad($unpadded, 10, '0', STR_PAD_LEFT);
    }

    $data = str_replace(array('{unique_id}', '{member_id}'), $memberNumber, $template);
    $data = preg_replace('/unique_id=[0-9A-Za-z_-]+/', 'unique_id=' . $memberNumber, $data);
    $data = preg_replace('/uid=[0-9A-Fa-f]+/', 'uid=' . $uid, $data);
    $data = preg_replace('/ctr=[0-9A-Fa-f]+/', 'ctr=' . $ctr, $data);
    $data = preg_replace('/cmac=[0-9A-Fa-f]+/', 'cmac=' . $cmac, $data);
    $data = preg_replace('/&c=[0-9A-Fa-f]+/', '&c=' . $cmac, $data);

    return $data;
}

/**
 * @param string $dynamicFileData
 * @param int $inputOffset
 * @param int $macOffset
 * @return string
 */
function ntag424ExtractMacInput($dynamicFileData, $inputOffset, $macOffset) {
    if ($inputOffset === $macOffset) {
        return '';
    }

    if ($macOffset <= $inputOffset) {
        return '';
    }

    return substr($dynamicFileData, $inputOffset, $macOffset - $inputOffset);
}

/**
 * @param array<string, mixed> $params Request parameters (uid, ctr, cmac/c, e, unique_id)
 * @param array<string, mixed>|null $member Member row for template substitution
 * @return array{verified: bool, card_uid: string|null, counter: int|null, reason: string|null}
 */
function ntag424VerifySdm($params, $member = null) {
    global $ntag424_master_key, $ntag424_meta_read_key, $ntag424_use_key_diversification;
    global $ntag424_sdm_url_template, $ntag424_sdm_mac_input_offset, $ntag424_sdm_mac_offset;

    if (!ntag424HasSdmParams($params)) {
        return array(
            'verified' => false,
            'card_uid' => null,
            'counter' => null,
            'reason' => 'missing_sdm_params',
        );
    }

    $cmacHex = !empty($params['cmac']) ? $params['cmac'] : $params['c'];
    $receivedMac = ntag424HexToBin($cmacHex);
    if ($receivedMac === null || strlen($receivedMac) !== 8) {
        return array(
            'verified' => false,
            'card_uid' => null,
            'counter' => null,
            'reason' => 'invalid_cmac',
        );
    }

    $masterKey = ntag424HexToBin($ntag424_master_key);
    if ($masterKey === null || strlen($masterKey) !== 16) {
        return array(
            'verified' => false,
            'card_uid' => null,
            'counter' => null,
            'reason' => 'invalid_master_key_config',
        );
    }

    $uidHex = null;
    $counter = null;
    $ctrBytes = null;
    $uidBin = null;

    if (!empty($params['e']) || !empty($params['picc_data'])) {
        $encrypted = !empty($params['e']) ? $params['e'] : $params['picc_data'];
        $metaKey = ntag424HexToBin($ntag424_meta_read_key);
        if ($metaKey === null || strlen($metaKey) !== 16) {
            return array(
                'verified' => false,
                'card_uid' => null,
                'counter' => null,
                'reason' => 'invalid_meta_read_key_config',
            );
        }

        $picc = ntag424DecryptPiccData($encrypted, $metaKey);
        if ($picc === null) {
            return array(
                'verified' => false,
                'card_uid' => null,
                'counter' => null,
                'reason' => 'picc_decrypt_failed',
            );
        }

        $uidHex = $picc['uid'];
        $counter = $picc['counter'];
        $ctrBytes = $picc['ctr_bytes'];
        $uidBin = $picc['uid_bin'];
    } else {
        $uidHex = strtoupper(preg_replace('/[^0-9a-fA-F]/', '', $params['uid']));
        $ctrHex = !empty($params['ctr']) ? $params['ctr'] : $params['counter'];
        $counter = ntag424ParseCounter($ctrHex);
        if ($counter === null) {
            return array(
                'verified' => false,
                'card_uid' => null,
                'counter' => null,
                'reason' => 'invalid_counter',
            );
        }

        $uidBin = ntag424HexToBin($uidHex);
        if ($uidBin === null || strlen($uidBin) !== 7) {
            return array(
                'verified' => false,
                'card_uid' => null,
                'counter' => null,
                'reason' => 'invalid_uid',
            );
        }

        $ctrBytes = ntag424CounterToBytes($counter);
    }

    $sdmFileReadKey = $masterKey;
    if (!empty($ntag424_use_key_diversification)) {
        $sdmFileReadKey = ntag424DeriveDiversifiedKey($masterKey, $uidBin);
    }

    $sessionMacKey = ntag424DeriveSessionMacKey($sdmFileReadKey, $uidBin, $ctrBytes);

    $uniqueId = '';
    if ($member !== null) {
        $uniqueId = $member['member_id'] ?? ($member['unique_id'] ?? '');
    } elseif (!empty($params['member_id'])) {
        $uniqueId = $params['member_id'];
    } elseif (!empty($params['unique_id'])) {
        $uniqueId = $params['unique_id'];
    }
    $ctrHexDisplay = str_pad(strtoupper(dechex($counter)), 6, '0', STR_PAD_LEFT);
    $dynamicFileData = ntag424BuildDynamicFileData(
        $ntag424_sdm_url_template,
        $uniqueId,
        $uidHex,
        $ctrHexDisplay,
        strtoupper($cmacHex)
    );

    $macInput = ntag424ExtractMacInput(
        $dynamicFileData,
        (int) $ntag424_sdm_mac_input_offset,
        (int) $ntag424_sdm_mac_offset
    );

    $computedMac = ntag424AesCmacTruncated($sessionMacKey, $macInput);
    if (!hash_equals($computedMac, $receivedMac)) {
        return array(
            'verified' => false,
            'card_uid' => $uidHex,
            'counter' => $counter,
            'reason' => 'cmac_mismatch',
        );
    }

    return array(
        'verified' => true,
        'card_uid' => $uidHex,
        'counter' => $counter,
        'reason' => null,
    );
}

/**
 * @param array<string, mixed>|null $member
 * @param array{verified: bool, card_uid: string|null, counter: int|null, reason: string|null} $sdmResult
 * @return bool
 */
function ntag424CheckReplayAndBinding($member, $sdmResult) {
    if (!$sdmResult['verified'] || $member === null || $sdmResult['counter'] === null) {
        return false;
    }

    $storedCounter = $member['last_read_counter'];
    if ($storedCounter !== null && (int) $sdmResult['counter'] <= (int) $storedCounter) {
        return false;
    }

    if (!empty($member['card_uid']) && !empty($sdmResult['card_uid'])) {
        if (strcasecmp($member['card_uid'], $sdmResult['card_uid']) !== 0) {
            return false;
        }
    }

    return true;
}
