#!/usr/bin/php
<?php

function acd_verify_argv($argv, $count)
{
    if (count($argv) < $count) {
        echo "ACD NOT ENOUGH PARAMETERS\n";
        exit(1);
    }
}

function acd_request($method, $url, $token, $data = null)
{
    $headers = array(
        'Content-Type:application/json',
        'accept: application/json',
    );

    if ($token) {
        $headers[] = "Authorization: Bearer $token";
    }

    $ch = curl_init($url);
    if ($method == "POST") {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }
    if ($method == "PUT") {
        curl_setopt($ch, CURLOPT_PUT, true);
    }
    if ($method == "DELETE") {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
//     curl_setopt($ch, CURLOPT_VERBOSE, true);

    $result = curl_exec($ch);
    if (curl_errno($ch)) {
        echo 'Error: ' . curl_error($ch);
        exit(0);
    }

    $response = json_decode($result, true);
    if (!is_array($response)) {
        echo "ACD INTERNAL ERROR\r\n";
        exit(1);
    }

//     print_r($response);
    return $response;
}

function acd_token($url, $user, $pass)
{
    $response = acd_request(
        "POST",
        $url . "/login",
        null,
        [
            'username' => $user,
            'password' => $pass
        ]
    );
    if (array_key_exists("token", $response)) {
        echo sprintf("ACDTOKENOK %s\n", $response['token']);
    } else {
        echo "ACDTOKENFAIL INTERNAL ERROR\r\n";
    }
}

function acd_status($url, $token, $agent)
{
    $response = acd_request(
        "GET",
        $url . "/agent/pausestatus/$agent",
        $token
    );

    if (array_key_exists("status", $response) && $response['status'] == "Paused") {
        echo "ACDSTATUS PAUSED\r\n";
    } elseif (array_key_exists("status", $response) && $response['status'] == "Not Paused") {
        echo "ACDSTATUS UNPAUSED\r\n";
    } else {
        echo "ACDSTATUSFAIL INTERNAL ERROR\r\n";
    }
}

function acd_login($url, $token, $agent, $interface)
{
    $payload = [
        "agent" => $agent,
        "interface" => $interface,
    ];

    $response = acd_request(
        "POST",
        $url . "/agent/login",
        $token,
        $payload
    );

    if (array_key_exists("status", $response) && $response['status'] == "Logged-in") {
        echo "ACDLOGINOK AGENT LOGGED IN\r\n";
    } elseif (array_key_exists("message", $response) && $response['message'] == "Agent already logged in") {
        echo "ACDLOGINFAIL AGENT ALREADY LOGGED IN\r\n";
    } else {
        echo "ACDLOGINFAIL UNABLE TO LOG IN\r\n";
    }
}

function acd_logout($url, $token, $agent, $interface)
{
    $payload = [
        "agent" => $agent,
        "interface" => $interface,
    ];

    $response = acd_request(
        "POST",
        $url . "/agent/logout",
        $token,
        $payload
    );

    if (array_key_exists("status", $response) && $response['status'] == "Logged-out") {
        echo "ACDLOGOUTOK AGENT LOGGED OUT\r\n";
    } elseif (array_key_exists("message", $response) && $response['message'] == "Agent not logged in") {
        echo "ACDLOGINFAIL AGENT ALREADY LOGGED IN\r\n";
    } else {
        echo "ACDLOGOUTFAIL INTERNAL ERROR\r\n";
    }
}

function acd_pause($url, $token, $agent, $interface, $code)
{
    // Validate custom pause code
    if ($code) {
        $valid_code = false;
        $response = acd_request("GET", $url . "/agent/listcustompause", $token);
        foreach ($response as $custompause) {
            if ($custompause['cod_pause'] == $code) {
                $valid_code = true;
                break;
            }
        }
        if (!$valid_code) {
            echo "ACDPAUSEFAIL UNKNOWN PAUSE CODE\r\n";
            exit(1);
        }
    }

    // Different endpoint for custom pauses
    if ($code) {
        $url .= "/agent/custompause/$agent/$interface/$code";
    } else {
        $url .= "/agent/pause/$agent/$interface";
    }

    $response = acd_request(
        "PUT",
        $url,
        $token
    );

    if (array_key_exists("status", $response) && $response['status'] == "Paused") {
        echo "ACDPAUSEOK AGENT PAUSED\r\n";
    } elseif (array_key_exists("message", $response) && $response['message'] == "Agent not logged in") {
        echo "ACDPAUSEFAIL AGENT NOT LOGGED IN\r\n";
    } elseif (array_key_exists("message", $response) && $response['message'] == "Agent already paused") {
        echo "ACDPAUSEFAIL AGENT ALREADY PAUSED\r\n";
    } else {
        echo "ACDPAUSEFAIL INTERNAL ERROR\r\n";
    }
}

function acd_unpause($url, $token, $agent, $interface)
{
    // Check if already paused
    $response = acd_request("GET", $url . "/agent/loginstatus/$agent", $token);
    if (is_array($response) && array_key_exists("status", $response) && $response['status'] != "Logged") {
        echo "ACDUNPAUSEFAIL AGENT NOT LOGGED IN\r\n";
    }

    $response = acd_request(
        "PUT",
        $url . "/agent/unpause/$agent/$interface",
        $token
    );

    if (array_key_exists("status", $response) && $response['status'] == "Unpaused") {
        echo "ACDUNPAUSEOK AGENT UNPAUSED\r\n";
    } elseif (array_key_exists("message", $response) && $response['message'] == "Agent not logged in") {
        echo "ACDUNPAUSEFAIL AGENT NOT LOGGED IN\r\n";
    } elseif (array_key_exists("message", $response) && $response['message'] == "Agent not paused") {
        echo "ACDUNPAUSEFAIL AGENT ALREADY UNPAUSED\r\n";
    } else {
        echo "ACDUNPAUSEFAIL INTERNAL ERROR\r\n";
    }
}

function acd_join($url, $token, $agent, $queue, $priority = null)
{
    $payload = [
        "agent" => $agent,
        "queue" => $queue,
    ];

    if ($priority) {
        $payload['prioridad'] = $priority;
    }

    $response = acd_request(
        "POST",
        $url . "/queue/addagent",
        $token,
        $payload
    );

    if (array_key_exists("status", $response) && $response['status'] == "Agent $agent added to queue $queue") {
        echo "QUEUEJOINOK Successfully JOIN queue $queue\r\n";
    } else {
        echo "QUEUEJOIFAIL Unable to JOIN queue $queue\r\n";
    }
}

function acd_leave($url, $token, $agent, $queue)
{
    $response = acd_request(
        "DELETE",
        $url . "/queue/removeagent/$agent/$queue",
        $token
    );

    if (array_key_exists("status", $response) && $response['status'] == "Agent $agent removed from queue $queue") {
        echo "QUEUELEAVEOK Successfully LEAVE queue $queue\r\n";
    } else {
        echo "QUEUELEAVEFAIL Unable to LEAVE queue $queue\r\n";
    }
}

// Minimal command line parameters
acd_verify_argv($argv, 3);
$action = strtoupper($argv[1]);
$url = rtrim($argv[2], "/");

if ($action == "STATUS" || $action == "TOKEN") {
    acd_verify_argv($argv, 5);
} else {
    acd_verify_argv($argv, 6);
}

switch ($action) {
    case "TOKEN":
        acd_token($url, $argv[3], $argv[4]);
        break;
    case "STATUS":
        acd_status($url, $argv[3], $argv[4]);
        break;
    case "LOGIN":
        acd_login($url, $argv[3], $argv[4], $argv[5]);
        break;
    case "LOGOUT":
        acd_logout($url, $argv[3], $argv[4], $argv[5]);
        break;
    case "PAUSE":
        acd_pause($url, $argv[3], $argv[4], $argv[5], (count($argv) > 7) ? $argv[6] : null);
        break;
    case "UNPAUSE":
        acd_unpause($url, $argv[3], $argv[4], $argv[5]);
        break;
    case "JOIN":
        acd_join($url, $argv[3], $argv[4], $argv[5], (count($argv) > 7) ? $argv[6] : null);
        break;
    case "LEAVE":
        acd_leave($url, $argv[3], $argv[4], $argv[5]);
        break;
}