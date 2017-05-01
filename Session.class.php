<?php
namespace kyegil\sessions;

class Session {

/**********************************************************************
Use an existing mysqli connection,
and pass it to the Session's constructor via its config object
***********************************************************************
*/
public	$mysqli;

/**********************************************************************
Make sure you have a db table for storing the session,
and submit the table and fields names to Session's constructor
***********************************************************************
*/
public		$db; //	In case there's need to switch database for session storage
protected	$defaultDb; //	Temporary storage of old db name in order to switch back after queries
public		$dbSessionsTable			= "sessions";
public		$dbSessionsIdField			= "id";
public		$dbSessionsTimestampField	= "start";
public		$dbSessionsTimestampFormat	= "U";
public		$dbSessionsKeyField			= "key";
public		$dbSessionsDataField		= "data";
public		$sessionSerializeHandler	= 'php_serialize';

/**********************************************************************
Allowing session ID as URL GET Parameter is highly discouraged
***********************************************************************
*/
public	$allowUrlSession = false;

/**********************************************************************
How many bits per character of the hash.
	4: (0-9, a-f)
	5: (0-9, a-v)
	6: (0-9, a-z, A-Z, -, ",")
***********************************************************************
*/
public	$sessionHashBitsPerCharacter = 5;

/**********************************************************************
In case you want to change the hash logarithm or salt,
pass it to Session's constructor via the config object
***********************************************************************
*/
public	$sessionHash = 'sha512';
private	$salt = 'cH!swe!retReGu7W6bEDRup7usuDUh9THeD2CHeGE*ewr4n39=E@rAsp7c-Ph@pH';



public function __construct( $config ) {
	settype( $config, 'object' );
	foreach( $config as $property => $value ) {
		if( property_exists($this, $property) ) {
			$this->$property = $value;
		}
	}

	session_set_save_handler(
		array($this, 'open'),
		array($this, 'close'),
		array($this, 'read'),
		array($this, 'write'),
		array($this, 'destroy'),
		array($this, 'gc')
	);

	register_shutdown_function('session_write_close');
}


public function start($sessionName, $secure) {

	if (session_status() != PHP_SESSION_NONE) {
		return;
	}

	// Check if hash is available
	if (in_array($this->sessionHash, hash_algos())) {
		ini_set('session.hash_function', $this->sessionHash);
	}
	
	ini_set('session.hash_bits_per_character', $this->sessionHashBitsPerCharacter);
	ini_set('session.serialize_handler', $this->sessionSerializeHandler);
	ini_set('session.use_only_cookies', ( $this->allowUrlSession ? 0 : 1 ));

	$cookieParams = session_get_cookie_params(); 
	session_set_cookie_params(
		$cookieParams["lifetime"],
		$cookieParams["path"],
		$cookieParams["domain"],
		$secure,
		true
	); 

	session_name($sessionName);

	session_start();

	// When session id is 60 seconds old there's 10% chance it will regenerate
	if(
		(time() - @$_SESSION['session_id_timestamp']) > 60
		and rand(0,9) == 0
	) {
/*
	The following two lines have been commented out on suspicion they cause the session ending prematurely
*/
//		$_SESSION['session_id_timestamp'] = time();
//		session_regenerate_id(true);
	}
}


public function open( $savePath, $sessionName ) {
	if( $this->mysqli instanceof \Mysqli ) {
		return true;
	}
	return false;
}


public function close() {
	return true;
}


public function read($sessionId) {
	if( $this->db ) {
		$this->defaultDb = $this->mysqli->query("SELECT DATABASE()")->fetch_row()[0];
		$this->mysqli->select_db($this->db);
	}

	$stmt = $this->mysqli->prepare("SELECT {$this->dbSessionsDataField} FROM {$this->dbSessionsTable} WHERE {$this->dbSessionsIdField} = ? LIMIT 1");

	$stmt->bind_param('s', $sessionId);
	$stmt->execute();
	$stmt->store_result();
	$stmt->bind_result($data);
	$stmt->fetch();
	$key = $this->getkey($sessionId);
	$data = $this->decrypt($data, $key);

	if( $this->db ) {
		$this->mysqli->select_db($this->defaultDb);
	}
	return $data;
}


public function write($sessionId, $data) {

	if( $this->db ) {
		$this->defaultDb = $this->mysqli->query("SELECT DATABASE()")->fetch_row()[0];
		$this->mysqli->select_db($this->db);
	}

	// Get unique key
	$key = $this->getkey($sessionId);
	// Encrypt the data
	$data = $this->encrypt($data, $key);

	$time = date($this->dbSessionsTimestampFormat);

	$stmt = $this->mysqli->prepare("REPLACE INTO {$this->dbSessionsTable} ({$this->dbSessionsIdField}, {$this->dbSessionsTimestampField}, {$this->dbSessionsDataField}, {$this->dbSessionsKeyField}) VALUES (?, ?, ?, ?)");

	$stmt->bind_param('ssss', $sessionId, $time, $data, $key);
	$stmt->execute();

	if( $this->db ) {
		$this->mysqli->select_db($this->defaultDb);
	}

	return true;
}


public function destroy($sessionId) {
	if( $this->db ) {
		$this->defaultDb = $this->mysqli->query("SELECT DATABASE()")->fetch_row()[0];
		$this->mysqli->select_db($this->db);
	}

	$stmt = $this->mysqli->prepare("DELETE FROM {$this->dbSessionsTable} WHERE {$this->dbSessionsIdField} = ?");
	$stmt->bind_param('s', $sessionId);
	$stmt->execute();

	if( $this->db ) {
		$this->mysqli->select_db($this->defaultDb);
	}

	return true;
}


public function gc($lifetime) {

	if( $this->db ) {
		$this->defaultDb = $this->mysqli->query("SELECT DATABASE()")->fetch_row()[0];
		$this->mysqli->select_db($this->db);
	}

	$stmt = $this->mysqli->prepare("DELETE FROM {$this->dbSessionsTable} WHERE {$this->dbSessionsTimestampField} < ?");
	$old = date( $this->dbSessionsTimestampFormat, (time() - $lifetime) );
	$stmt->bind_param('s', $old);
	$stmt->execute();

	if( $this->db ) {
		$this->mysqli->select_db($this->defaultDb);
	}

	return true;
}


private function getkey($sessionId) {
	if( $this->db ) {
		$this->defaultDb = $this->mysqli->query("SELECT DATABASE()")->fetch_row()[0];
		$this->mysqli->select_db($this->db);
	}

	$stmt = $this->mysqli->prepare("SELECT {$this->dbSessionsKeyField} FROM {$this->dbSessionsTable} WHERE {$this->dbSessionsIdField} = ? LIMIT 1");
	$stmt->bind_param('s', $sessionId);
	$stmt->execute();
	$stmt->store_result();

	if($stmt->num_rows == 1) { 
		$stmt->bind_result($key);
		$stmt->fetch();

		if( $this->db ) {
			$this->mysqli->select_db($this->defaultDb);
		}

		return $key;
	}

	else {

		if( $this->db ) {
			$this->mysqli->select_db($this->defaultDb);
		}

		return hash('sha512', uniqid(mt_rand(1, mt_getrandmax()), true));
	}
}


private function encrypt($data, $key) {
	$key = substr(hash('sha256', $this->salt.$key.$this->salt), 0, 32);
	$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
	$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
	
	$result = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_ECB, $iv));
	
	return $result;
}


private function decrypt($data, $key) {
	$key = substr( hash('sha256', $this->salt.$key.$this->salt), 0, 32 );
	$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
	$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
	
	$result = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, base64_decode($data), MCRYPT_MODE_ECB, $iv);
	$result = rtrim($result, "\0");
	
	return $result;
}


public function getAllSessions() {
	$result = array();
	
	$sql = "SELECT {$this->dbSessionsIdField} AS id, {$this->dbSessionsTimestampField} AS timestamp, {$this->dbSessionsKeyField} AS session_key, {$this->dbSessionsDataField} AS data FROM {$this->dbSessionsTable}";
	
	$sessions = $this->mysqli->query($sql);
	
	if($sessions === false) {
		throw new \Exception("SQL Error:\n{$sql}\n");
	}
	
	while($session = $sessions->fetch_object()) {
		$session->timestamp
			= date_create_from_format(
				$this->dbSessionsTimestampFormat,
				$session->timestamp
			);

			$data = $this->decrypt($session->data, $session->session_key);
			$session->data = unserialize($data);
			
			if( $session->id == session_id() ) {
				$session->available = true;
			}
			else {
				$session->available = false;
			}

		$result[] = $session;
	}

	$sessions->free();
	
	return $result;
}


}