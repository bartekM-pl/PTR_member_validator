<?php

require_once __DIR__ . '/../config.php';

/**
 * @return mysqli
 */
function getDbConnection() {
    global $sql_address, $sql_login, $sql_pass, $sql_dbname;

    $conn = new mysqli($sql_address, $sql_login, $sql_pass, $sql_dbname);
    if ($conn->connect_error) {
        throw new RuntimeException('Database connection failed: ' . $conn->connect_error);
    }

    $conn->set_charset('utf8mb4');

    return $conn;
}

/**
 * @param mysqli $conn
 * @param string $sql
 * @param string $types
 * @param array $params
 * @return array<int, array<string, mixed>>
 */
function dbFetchAll($conn, $sql, $types = '', $params = array()) {
    $stmt = $conn->prepare($sql);
    if ($stmt === false) {
        throw new RuntimeException('Failed to prepare query: ' . $conn->error);
    }

    if ($types !== '' && !empty($params)) {
        $bindParams = array($types);
        foreach ($params as $key => $value) {
            $bindParams[] = &$params[$key];
        }
        call_user_func_array(array($stmt, 'bind_param'), $bindParams);
    }

    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();
        throw new RuntimeException('Failed to execute query: ' . $error);
    }

    $result = $stmt->get_result();
    $rows = array();
    if ($result !== false) {
        while ($row = $result->fetch_assoc()) {
            $rows[] = $row;
        }
    }

    $stmt->close();

    return $rows;
}

/**
 * @param mysqli $conn
 * @param string $sql
 * @param string $types
 * @param array $params
 * @return int
 */
function dbExecute($conn, $sql, $types = '', $params = array()) {
    $stmt = $conn->prepare($sql);
    if ($stmt === false) {
        throw new RuntimeException('Failed to prepare query: ' . $conn->error);
    }

    if ($types !== '' && !empty($params)) {
        $bindParams = array($types);
        foreach ($params as $key => $value) {
            $bindParams[] = &$params[$key];
        }
        call_user_func_array(array($stmt, 'bind_param'), $bindParams);
    }

    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();
        throw new RuntimeException('Failed to execute query: ' . $error);
    }

    $affected = $stmt->affected_rows;
    $stmt->close();

    return $affected;
}
