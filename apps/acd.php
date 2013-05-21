#!/usr/bin/php
<?php

define("CHK_KARMA", "1");
define("BASE_URL", "/var/www/ivozng/karma/libs/");
define("DB_CON", "asterisk");
require_once(BASE_URL."autoload.php");

$server="http://127.0.0.1:8088";    // The server to connect to
$amiuser="ironadmin";
$password="adminsecret";


if ($argc != 4) { 
	echo "ACD NOT ENOUGH PARAMETERS\n";	
	exit(1);
}


/*
	FIXME
	Se reciben siempre 3 parametros, pero solo en el caso de login se recibe: interface | agente | operacion
	en el resto de casos, la entrada esta dupicada, en pause/unpause/logof, se recibe: agente | agente | operacion

	Esto no afecta en nada, pero es importante tenerlo controlado :)
	Se controla en el siguiente bloque, cuando se intenta localizar la extension SIP


	10/12/2009
*/
$interface = $argv[1];
$agente = $argv[2];
$op = strtoupper($argv[3]);

$iacd = new IronACD($agente); //Instanciamos IronACD() para utilizar todas las funciones que necesitemos.
$ami = new AJAM($server,$amiuser,$password);

/*
	LOCALIZACION DE LA EXTENSION SIP 
	===============================
	Explicacion: Cuando se hace un login, si se tiene la extension SIP ya que AIBE la envia en el AgentCallBackLogin
	Cuando se envia cualquier otra cosa, no se tiene, asi que hay que buscarla y viene bien sobre todo para la funcion storeAgentInfo
*/
if ($op != "LOGIN")
{
	$interfaz = $iacd->getAgentInterface($agente);
	if (is_null($interfaz))
	{
		// Este caso sucedera bastante ya que AIBE envia un pause muchas veces antes de un Login, es asi el tema :)
		echo "ACD${op}FAIL AGENT NOT LOGGED IN\n";
		exit(1);
	}

       	$partes = explode('/',$interfaz);		// Explodeamos para quitar SIP/
       	$interface = $partes[1];    			// Y tenemos ya tal cual la extension sip pura :D)
}

$iacd->setSIPpeer($interface); //Seteamos el peer SIP para poder utilizarlo en las funciones de IronACD()

switch ($op){
	case "LOGIN":
		if (!$iacd->agentAlreadyOn()) {
			if ($iacd->queueLoginSuper()) {
				echo "ACDLOGINOK AGENT LOGGED IN\n";
			} else {
				echo "ACDLOGINFAIL UNABLE TO LOG IN\n";
			}
		} else {
			echo "ACDLOGINFAIL AGENT ALREADY LOGGED IN\n";
		}
	break;
	case "LOGOUT":
		if ($iacd->agentAlreadyOn()) { 
                	if ($iacd->queueLogoffSuper()) {
				$iacd->storeAgentInfo("LOGOFF");
				echo "ACDLOGOUTOK AGENT LOGGED OUT\n";
                	} else {
				echo "ACDLOGOUTFAIL UNABLE TO LOG OUT\n";
                	}
		} else {
			echo "ACDLOGOUTOK AGENT NOT LOGGED IN\n";
		}
	break;
	case "PAUSE":
		if ($iacd->agentPauseSuper()) {
			echo "ACDPAUSEOK AGENT PAUSED\n";
        	} else {
			echo "ACDPAUSEFAIL AGENT ALREADY PAUSED\n";
        	}
	break;
	case "UNPAUSE":
		if ($iacd->agentPauseSuper(false)) {
			echo "ACDUNPAUSEOK AGENT UNPAUSED\n";
	        } else {
			echo "ACDUNPAUSEFAIL AGENT ALREADY UNPAUSED\n";
	        }
	break;
}

exit(0);

?>
