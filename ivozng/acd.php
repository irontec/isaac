#!/usr/bin/php
<?php

define("CHK_KARMA", "1");
define("BASE_URL", "/var/www/ivozng/karma/libs/");
define("DB_CON", "asterisk");
require_once(BASE_URL."autoload.php");

$server="http://127.0.0.1:8088";    // The server to connect to
$amiuser="AMI_USER";
$password="AMI_SECRET";

if ($argc < 4) {
	echo "ACD NOT ENOUGH PARAMETERS\n";
	exit(1);
}

$interface = $argv[1];
$agente = $argv[2];
$op = strtoupper($argv[3]);

$iacd = new IronACD($agente); //Instanciamos IronACD() para utilizar todas las funciones que necesitemos.
$ami = new AJAM($server,$amiuser,$password);


if ($op != "LOGIN")
{
	$interfaz = $iacd->getAgentInterface($agente);
	if (is_null($interfaz)) {
		fwrite(STDERR, "ACD${op}FAIL AGENT NOT LOGGED IN\r\n");
	}

	$partes = explode('/',$interfaz);		// Explodeamos para quitar SIP/
	$interface = $partes[1];    			// Y tenemos ya tal cual la extension sip pura :D)
}


// Set Agent interface
$iacd->setSIPpeer($interface);

switch ($op){
	case "STATUS":
		if (!$iacd->agentAlreadyOn()) {
			fwrite(STDERR, "ACDSTATUS NOT LOGGED IN\r\n");
		} else {
			$id_pausa = $iacd->isAgentPausedNEW();
			if (!is_null($id_pausa) && !$id_pausa) {
				fwrite(STDERR, "ACDSTATUS UNPAUSED\r\n");
			} else {
				fwrite(STDERR, "ACDSTATUS PAUSED\r\n");
			}
		}
		break;
	case "LOGIN":
		if ($iacd->agentAlreadyOn()) {
			fwrite(STDERR, "ACDLOGINFAIL AGENT ALREADY LOGGED IN\r\n");
			break;
		}
		$iacd->setSIPpeer($interface);
		if ($iacd->queueLoginSuper()) {
			$ami->login();
			$ami->devstate("access",$interface,"NOT_INUSE");
			$ami->logoff();
			fwrite(STDERR, "ACDLOGINOK AGENT LOGGED IN\r\n");
		} else {
			fwrite(STDERR, "ACDLOGINFAIL UNABLE TO LOG IN\r\n");
		}
		break;
	case "LOGOUT":
		if (!$iacd->agentAlreadyOn()) {
			fwrite(STDERR, "ACDLOGOUTOK AGENT NOT LOGGED IN\r\n");
			break;
		}
		if ($iacd->queueLogoffSuper()) {
			$ami->login();
			$ami->devstate("pause",$interface,"NOT_INUSE");
			$iacd->storeAgentInfo("LOGOFF");
			$ami->devstate("access",$interface,"INUSE");
			$ami->logoff();
			fwrite(STDERR, "ACDLOGOUTOK AGENT LOGGED OUT\r\n");
		} else {
			fwrite(STDERR, "ACDLOGOUTFAIL UNABLE TO LOG OUT\r\n");
		}

		break;
	case "PAUSE":
        // Check agent is logged in
		if (!$iacd->agentAlreadyOn()) {
			fwrite(STDERR, "ACDPAUSEFAIL AGENT NOT LOGGED IN\r\n");
			break;
		}

        // Check we have a custom pause id
        $pausecode = strtoupper($argv[4]);
        if (is_null($pausecode) || empty($pausecode)) {
	        if ($iacd->agentPauseSuper()) {
		    	$ami->login();
		    	$ami->devstate("pause",$interface,"RINGING");
		    	$ami->logoff();
		    	fwrite(STDERR, "ACDPAUSEOK AGENT PAUSED\r\n");
		    } else {
		    	fwrite(STDERR, "ACDPAUSEFAIL AGENT ALREADY PAUSED\r\n");
		    }
        } else {
            // Get the id_pausa from its code
            $sql = "SELECT id_pausa FROM callcenter_pausas WHERE cod_pausa = '$pausecode'";
            $con = new con($sql, DB_CON);
            if ($con->getError() || !$con->getNumRows()) {
                fwrite(STDERR, "ACDPAUSEFAIL UNKOWN PAUSE CODE\r\n");
                break;
            } 

            // Get Agent queue information
            $r =  $con->getResult();

            // Pause Custom
            if ($iacd->agentPauseCustom($r['id_pausa'])) {
                $ami->login();
                $ami->devstate("pause",$interface,"RINGING");
                $ami->logoff();
                fwrite(STDERR, "ACDPAUSEOK AGENT PAUSED\r\n");
            } else {
                fwrite(STDERR, "ACDPAUSEFAIL AGENT ALREADY PAUSED\r\n");
            } 
        }
		break;
	case "UNPAUSE":
		if (!$iacd->agentAlreadyOn()) {
			fwrite(STDERR, "ACDUNPAUSEFAIL AGENT NOT LOGGED IN\n");
			break;
		}
		if ($iacd->agentPauseSuper(false)) {
			$ami->login();
			$ami->devstate("pause",$interface,"NOT_INUSE");
			$ami->logoff();
			fwrite(STDERR, "ACDUNPAUSEOK AGENT UNPAUSED\r\n");
		} else {
			fwrite(STDERR, "ACDUNPAUSEFAIL AGENT ALREADY UNPAUSED\r\n");
		}
		break;
    case "JOIN":
    case "LEAVE":

        // Parse remaining arguments
        $args = explode(" ", trim($argv[4]));

        // Check we have a queuename
        $cola = strtoupper($args[0]);
        if (is_null($cola) || empty($cola)) {
			fwrite(STDERR, "QUEUE${op}FAILED Queuename is required\r\n");
            break;
        }
    
        // Check if the agent can login in given queue
        $sql = "SELECT r.penalty, r.ringinuse
            FROM ast_queues AS q 
            LEFT JOIN callcenter_rel_queues_agents AS r ON q.id_queue = r.id_queue 
            LEFT JOIN karma_usuarios AS k ON r.id_agent = k.id_usuario
            WHERE q.name = '$cola' and k.login_num = '$agente'";

        $con = new con($sql, DB_CON);
        if ($con->getError() || !$con->getNumRows()) {
            fwrite(STDERR, "QUEUE${op}FAILED Agent $agente has no rights on queue $cola\r\n");
            break;
        } 

        // Get Agent queue information
        $r =  $con->getResult();
        
        // Check if command specifies priority
        if (isset($args[1])) {
            $priority = $args[1]; 
        } else {
            $priority = $r['penalty'];
        }

        // Check we have a valid priority
        if (!is_numeric($priority)) {
            fwrite(STDERR, "QUEUE${op}FAIL Priority $priority is not numeric\r\n");
            break;
        }

        // Always Leave the queue
        $iacd->queueJoinLeaveManual(false,  $cola, $priority, $r['ringinuse']);

        // Join/Leave Queue
        if ($iacd->queueJoinLeaveManual(($op == "JOIN"), $cola, $priority, $r['ringinuse']) == true) {
            fwrite(STDERR, "QUEUE${op}OK Successfully ${op} queue $cola\r\n");
        } else {
            fwrite(STDERR, "QUEUE${op}FAIL Unable to ${op} queue $cola\r\n");
        }
}

exit(0);

?>
