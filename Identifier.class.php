<?php
namespace kyegil\sessions;

class Identifier {

/**********************************************************************
Include access to the session handler class
***********************************************************************
*/
public	$sessionHandler;

/**********************************************************************
Explanations of failed operations will be available as error code in the
errors property as follows:

100: Registrations

120: Password validation
121: The password is too short
122: The password is too long
123: The password contains illegal characters
124: The password does not contain the required characters

130: Email validation
133: The email contains illegal characters
135: The email address is taken

140: Login (username) validation
141: The login is too short
142: The login is too long
143: The login contains illegal characters
144: The login does not contain the required characters
145: The username is taken

***********************************************************************
*/
public	$errors;

/**********************************************************************
Use an existing mysqli connection,
and pass it to the Identifiers's constructor via its config object
***********************************************************************
*/
public	$mysqli;

/**********************************************************************
Make sure you have a db table for storing the username and password,
and submit the table and fields names to Identifiers's constructor
***********************************************************************
*/
public	$dbUsersTable;
public	$dbIdField;
public	$dbLoginField;
public	$dbEmailField;
public	$dbPasswordField;
public	$dbAdditionalUserFields = array();
public	$allowCrossBrowserSessions = false;

/**********************************************************************
Use the following configurations to record failed logings
in order to prevent brute force attacks
To disable this function set max login attempts to 0
***********************************************************************
*/
public	$failedLoginsTable;
public	$failedLoginsLoginField = "username";
public	$failedLoginsField = "username";
public	$maxLoginAttempts = 0;
public	$maxLoginAttemptsTimeframe = 1800; // seconds
public	$minLoginInterval = 0; // seconds

/**********************************************************************
Requirements to user details
***********************************************************************
*/
public	$minPasswordLength = 4;
public	$maxPasswordLength;
public	$passwordAllowedRegex	= '';// = '/^[A-Za-z0-9ÆaØøÅå-*]+$/i';
public	$passwordProhibitedRegex;
public	$passwordRequiredRegex	= '';/* = '/(?=(?:.*?[A-ÆØÅ]){1}) # One uppercase letter required
								(?=(?:.*?[a-zæøå]){1}) # One lowercase letter required
								(?=(?:.*?[0-9]){1})		# One number required
					(?=(?:.*?[\;\:\.\!\@€\£#\$%\^&\*\(\)\-_\+\=\[\]\{\}\\\?\.\,\>\<\`\~\'\"\§\±\|]){1})/x';
*/
public	$minLoginLength = 2;
public	$maxLoginLength;
public	$loginAllowedCharacters;
public	$loginProhibitedCharacters;
public	$loginRequiredCharacters;


public function __construct( $config ) {
	settype( $config, 'object' );
	foreach( $config as $property => $value ) {
		if( property_exists($this, $property) ) {
			$this->$property = $value;
		}
	}
}


/*	Check if logged in
This function checks if you are currently logged in as a user
******************************************
------------------------------------------
return: (boolean) true if you're logged in, false if not
*/
public function checkIfLoggedIn() {
	if (
		isset(
			$_SESSION['current_user'], 
			$_SESSION['logged_in_users']
		)
		and is_object(@$_SESSION['logged_in_users'][$_SESSION['current_user']])
		and isset(
			$_SESSION['logged_in_users'][$_SESSION['current_user']]->loginString,
			$_SESSION['logged_in_users'][$_SESSION['current_user']]->login
		)
	) {

		$user = $_SESSION['logged_in_users'][$_SESSION['current_user']];

		// Get the user-agent string of the user.
		$browser = $_SERVER['HTTP_USER_AGENT'];

		if ($stmt = $this->mysqli->prepare("SELECT {$this->dbPasswordField} AS password 
		FROM {$this->dbUsersTable} 
		WHERE {$this->dbLoginField} = ? LIMIT 1")) {
			$stmt->bind_param('s', $user->login);
			$stmt->execute();
			$stmt->store_result();

			if ($stmt->num_rows == 1) {
				$stmt->bind_result($password);
				$stmt->fetch();

				if (hash_equals(
					hash('sha512', $password . $browser),
					$user->loginString
				) ) {
					return true;
				}
			}
		}
	}
	return false;
}


/*	Create token
Creates a token based on your encrypted password, login and the expiry timestamp.
Either login (username) or email must be provided to obtain a login token
******************************************
$token (string)
$login (optional string) The username of the user that requires a token
$timestamp (integer) The expiration timestamp 
$email (string) (optional string) The registered email address of the user that requires a token
------------------------------------------
return: (mixed) Returns the hashed token on success, a boolen false if not
*/
public function createToken($token, $login, $timestamp = null, $email = null
) {
	if(!$timestamp) {
		$timestamp = time() + 24 * 3600;
	}
	if( $email ) {
		$login = $this->getLoginFromEmail($email);
	}
	
	$sql = "SELECT\n"
		. "{$this->dbPasswordField} FROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbLoginField} != ?\n"
		. "LIMIT 1";

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('s', $login);
		$stmt->execute();
		$stmt->store_result();

		if ($stmt->num_rows == 1) {
			$stmt->bind_result($password);
			$stmt->fetch();

			return password_hash($password.$login.$timestamp, PASSWORD_BCRYPT);
		}
	}
	return false;
}


/*	Does user exist
Checks if a given username (login) exists in the database
******************************************
$login (string) The username of the user to look for
------------------------------------------
return: (boolean) True if the user exists, false otherwise
*/
public function doesUserExist(string $login) {
	$sql = "SELECT\n"
		. "{$this->dbLoginField} FROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbLoginField} = ?\n"
		. "LIMIT 1";

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('s', $login);
		$stmt->execute();
		$stmt->store_result();

		if ($stmt->num_rows == 1) {
			return true;
		}
		return false;
	}
	throw new Exception("Problem preparing mysqli_stmt");
}


/*	Edit User
Edit a specific user
******************************************
$login (string): The current login (username) of the user that's being edited
$newLogin (optional string): The new login if this is to be changed
$password (optional string): The new password if this is to be changed
$email (optional string): The new email if this is to be changed
$other (associated array or object): Other changes as key => new value
------------------------------------------
return: (boolean) Success
*/
public function editUser(
	string $login, 
	string $newLogin = null,
	string $password = null,
	string $email = null,
	$other = null 
) {
	settype($other, 'object');
	
	$sqlFields = array();
	$values = array('');

	if($newLogin) {
		if($this->validateLogin($newLogin)) {
			$sqlFields[] = "{$this->dbLoginField} = ?";
			$values[0] .= "s";
			$values[] = &$newLogin;
		}
		else {
			return false;
		}
	}
	if($password) {
		if($this->validatePassword($password)) {
			$password_hash = password_hash($password, PASSWORD_BCRYPT);
			$sqlFields[] = "{$this->dbPasswordField} = ?";
			$values[0] .= "s";
			$values[] = &$password_hash;
		}
		else {
			return false;
		}
	}
	if($email) {
		if(!$this->validateEmail($email)) {
			$sqlFields[] = "{$this->dbEmailField} = ?";
			$values[0] .= "s";
			$values[] = &$email;
		}
		else {
			return false;
		}
	}
	foreach( $other as $field => $value ) {
		$sqlFields[] = "{$field} = ?";
		$values[0] .= "s";
		$values[] = &$value;
	}

	$values[0] .= "s";
	$values[] = &$login;

	$sql =	"UPDATE {$this->dbUsersTable}\nSET\n"
		.	implode(',', $sqlFields)
		.	"\nWHERE {$this->dbLoginField} = ? \n";

	$stmt = $this->mysqli->prepare($sql);

	call_user_func_array(array($stmt, 'bind_param'), $values);
	$stmt->execute();
	
	return true;
}


/*	Escape Url
Escpae a url
******************************************
$url (string): The url to be escaped
------------------------------------------
return: (string) The escaped url
*/
public function escapeUrl(string $url) {
	if ('' == $url) {
		return $url;
	}

	$url = preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\\x80-\\xff]|i', '', $url);

	$strip = array('%0d', '%0a', '%0D', '%0A');
	$url = (string) $url;

	$count = 1;
	while ($count) {
		$url = str_replace($strip, '', $url, $count);
	}

	$url = str_replace(';//', '://', $url);

	$url = htmlentities($url);

	$url = str_replace('&amp;', '&#038;', $url);
	$url = str_replace("'", '&#039;', $url);

	if ($url[0] !== '/') {
		return '';
	} else {
		return $url;
	}
}


/*	Get all users
Returns all current users as an array of stdClass object with properties id and login
******************************************
------------------------------------------
return: (array) Array of stdClass objects:
	->id (string) The user's id
	->login (string) The user's login 
*/
public function getAllUsers() {
	$result = array();
	
	$sql = "SELECT " . ($this->dbIdField ? "{$this->dbIdField} AS id, " : "") . "{$this->dbLoginField} AS login FROM {$this->dbUsersTable}";
	
	$users = $this->mysqli->query($sql);
	
	while($user = $users->fetch_object()) {
		$result[] = $user;
	}

	$users->free();
	
	return $result;
}


/*	Get id from login
******************************************
$login (string): The user's login
------------------------------------------
return: (string or false) The id if the user exists, otherwise false
*/
public function getIdFromLogin(string $login) {
	if(!$this->dbIdField) {
		return false;
	}
	$sql = "SELECT\n"
		. "{$this->dbIdField} FROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbLoginField} = ?\n"
		. "LIMIT 1";

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('s', $login);
		$stmt->execute();
		$stmt->store_result();

		if ($stmt->num_rows == 1) {
			$stmt->bind_result($id);
			$stmt->fetch();

			return $id;
		}
		return false;
	}
	throw new Exception("Problem preparing mysqli_stmt");
}


/*	Get login from email
******************************************
$email (string): The user's email
------------------------------------------
return: (string or false) The login if the user exists, otherwise false
*/
public function getLoginFromEmail(string $email) {
	if(!$this->dbEmailField) {
		return false;
	}
	$sql = "SELECT\n"
		. "{$this->dbLoginField} FROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbEmailField} = ?\n"
		. "LIMIT 1";

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('s', $email);
		$stmt->execute();
		$stmt->store_result();

		if ($stmt->num_rows == 1) {
			$stmt->bind_result($login);
			$stmt->fetch();
			return $login;
		}
		return false;
	}
	throw new Exception("Problem preparing mysqli_stmt");
}


/*	Get login from id
******************************************
$id: The user's id
------------------------------------------
return: (string or false) The login if the user exists, otherwise false
*/
public function getLoginFromId($id) {
	if(!$this->dbIdField) {
		return false;
	}
	$sql = "SELECT\n"
		. "{$this->dbLoginField} FROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbIdField} = ?\n"
		. "LIMIT 1";

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('i', $id);
		$stmt->execute();
		$stmt->store_result();

		if ($stmt->num_rows == 1) {
			$stmt->bind_result($login);
			$stmt->fetch();

			return $login;
		}
		return false;
	}
	throw new Exception("Problem preparing mysqli_stmt");
}


/*	Get User
******************************************
$login (string): The user's login
------------------------------------------
*/
public function getUser($login) {
	$result = (object) array(
		'login'		=> null
	);
	$resultProperties = array(
		&$result->login
	);

	if( $this->dbIdField ) {
		$result->id = null;
		$resultProperties [] = &$result->id;
	}

	if( $this->dbEmailField ) {
		$result->email = null;
		$resultProperties [] = &$result->email;
	}

	foreach( $this->dbAdditionalUserFields as $additionalField) {
		$result->$additionalField = null;
		$resultProperties [] = &$result->$additionalField;
	}

	$sql = "SELECT\n"
		. "{$this->dbLoginField} AS login,\n"
		. "{$this->dbPasswordField} AS password,\n"
		.	( $this->dbIdField ? "{$this->dbIdField} AS id,\n" : "" )
		.	( $this->dbEmailField ? "{$this->dbEmailField} AS email,\n" : "" )
		.	( $this->dbAdditionalUserFields ? implode(', ',$this->dbAdditionalUserFields) : "" )
		. "\nFROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbLoginField} = ? \n"
		. "LIMIT 1"
	;

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('s', $login);
		$stmt->execute();    // Execute the prepared query.
		$stmt->store_result();

		// get variables from result.
		call_user_func_array(array($stmt, 'bind_result'), $resultProperties);
		$stmt->fetch();

		if ($stmt->num_rows == 1) {
			return $result;
		}
	}
	return false;
}


/*	Log in
Log the user in by login and password
******************************************
$login (string): The user's login
$password (string): The user's password
------------------------------------------
*/
public function login($login, $password) {
	$result = (object) array(
		'login'		=> null,
		'password'	=> null
	);
	$resultProperties = array(
		&$result->login,
		&$result->password
	);

	if( $this->dbIdField ) {
		$result->id = null;
		$resultProperties [] = &$result->id;
	}

	if( $this->dbEmailField ) {
		$result->email = null;
		$resultProperties [] = &$result->email;
	}

	foreach( $this->dbAdditionalUserFields as $additionalField) {
		$result->$additionalField = null;
		$resultProperties [] = &$result->$additionalField;
	}

	$sql = "SELECT\n"
		. "{$this->dbLoginField} AS login,\n"
		. "{$this->dbPasswordField} AS password,\n"
		.	( $this->dbIdField ? "{$this->dbIdField} AS id,\n" : "" )
		.	( $this->dbEmailField ? "{$this->dbEmailField} AS email" : "" )
		.	( $this->dbAdditionalUserFields ? (",\n" . implode(', ',$this->dbAdditionalUserFields)) : "\n" )
		. "\nFROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbLoginField} = ? \n"
		. "LIMIT 1"
	;

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('s', $login);
		$stmt->execute();    // Execute the prepared query.
		$stmt->store_result();

		// get variables from result.
		call_user_func_array(array($stmt, 'bind_result'), $resultProperties);
		$stmt->fetch();

		if ($stmt->num_rows == 1) {
			if ( $this->maxLoginAttempts and $this->checkBrute($result->login)) {
				return false;
			}

			else {
				// Check if password matches
				if (
					password_verify($password, $result->password)
					or md5($password) == $result->password
				) {

					$result->id = preg_replace("/[^0-9]+/", "", @$result->id);
					$result->login = strip_tags($result->login);
					
					if( $this->allowCrossBrowserSessions ) {
						$browser = "";
					}
					else {
						$browser = $_SERVER['HTTP_USER_AGENT'];
					}
					$result->loginString = hash(
						'sha512', 
						$result->password . $browser
					);
					
					unset($result->password);
					settype($_SESSION['logged_in_users'], 'array');					
					$_SESSION['logged_in_users'][$result->login] = $result;
					$_SESSION['current_user'] = $result->login;

					return true;
				}
				
				// Password is not correct
				else {
					if( $this->maxLoginAttempts ) {
					$now = time();
					$this->mysqli->query("INSERT INTO login_attempts (user_id, time)
					VALUES ('$result->login', '$now')");
					}
					return false;
				}
			}
		}
		else {
			return false;
		}
	}
}


/*	Log in by token
******************************************
------------------------------------------
*/
public function loginByToken($token, $login, $timestamp, $email = null) {
	if($timestamp < time()) {
		return false;
	}
	$result = (object) array(
		'login'		=> null,
		'password'	=> null
	);
	$resultProperties = array(
		&$result->login,
		&$result->password
	);

	if( $this->dbIdField ) {
		$result->id = null;
		$resultProperties [] = &$result->id;
	}

	$matchField = $this->dbLoginField;
	$matchValue = $login;
		
	if( $this->dbEmailField ) {
		$result->email = null;
		$resultProperties [] = &$result->email;
		$matchField = $this->dbEmailField;
		$matchValue = $email;
	}

	foreach( $this->dbAdditionalUserFields as $additionalField) {
		$result->$additionalField = null;
		$resultProperties [] = &$result->$additionalField;
	}

	$sql = "SELECT\n"
		. "{$this->dbLoginField} AS login,\n"
		. "{$this->dbPasswordField} AS password,\n"
		.	( $this->dbIdField ? "{$this->dbIdField} AS id,\n" : "" )
		.	( $this->dbEmailField ? "{$this->dbEmailField} AS email,\n" : "" )
		.	( $this->dbAdditionalUserFields ? implode(', ',$this->dbAdditionalUserFields) : "" )
		. "\nFROM {$this->dbUsersTable}\n"
		. "WHERE {$matchField} = ? \n"
		. "LIMIT 1"
	;

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('s', $matchValue);
		$stmt->execute();
		$stmt->store_result();

		// get variables from result.
		call_user_func_array(array($stmt, 'bind_result'), $resultProperties);
		$stmt->fetch();

		if ($stmt->num_rows == 1) {
			if ( $this->maxLoginAttempts and $this->checkBrute($result->login)) {
				return false;
			}

			else {
				if (
					password_verify(($password.$login.$timestamp), $token)
				) {

					$result->id = preg_replace("/[^0-9]+/", "", @$result->id);
					$result->login = strip_tags($result->login);
					
					if( $this->allowCrossBrowserSessions ) {
						$browser = "";
					}
					else {
						$browser = $_SERVER['HTTP_USER_AGENT'];
					}
					$result->loginString = hash(
						'sha512', 
						$result->password . $browser
					);
					
					unset($result->password);
					settype($_SESSION['logged_in_users'], 'array');					
					$_SESSION['logged_in_users'][$result->login] = $result;
					$_SESSION['current_user'] = $result->login;

					return true;
				}
				
				// Password is not correct
				else {
					if( $this->maxLoginAttempts ) {
					$now = time();
					$this->mysqli->query("INSERT INTO login_attempts (user_id, time)
					VALUES ('$result->login', '$now')");
					}
					return false;
				}
			}
		}
	}
	return false;
}


/*	Log out
******************************************
------------------------------------------
*/
public function logout($login = null) {
	if($login and isset($_SESSION['logged_in_users'], $_SESSION['logged_in_users'][$login])) {
		unset($_SESSION['logged_in_users'][$login]);
		if($_SESSION['current_user'] == $login) {
			$_SESSION['current_user'] = "";
		}
		return true;
	}
	else if($login === null) {
		$_SESSION = array();

		$params = session_get_cookie_params();
		setcookie(session_name(),
		'', time() - 42000, 
		$params["path"], 
		$params["domain"], 
		$params["secure"], 
		$params["httponly"]);

		session_destroy();
		return true;
	}
}


/*	Set current user
******************************************
------------------------------------------
*/
public function setCurrentUser($login) {
	if($login and isset($_SESSION['logged_in_users'], $_SESSION['logged_in_users'][$login])) {
		$_SESSION['current_user'] = $login;
		return true;
	}
	return false;
}


/*	Validate email
******************************************
------------------------------------------
*/
public function validateEmail(
	string $email,
	string $login = ""
) {
	if(!$this->dbEmailField) {
		return true;
	}
	if( strip_tags($email) !== $email ) {
		$this->errors = 143;
		return false;
	}

	$sql = "SELECT\n"
		. "{$this->dbLoginField} FROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbEmailField} = ? AND {$this->dbLoginField} != ?\n"
		. "LIMIT 1";

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('ss', $email, $login);
		$stmt->execute();
		$stmt->store_result();

		if ($stmt->num_rows == 1) {
			$this->errors = 135;
			return false;
		}
		return true;
	}
	throw new Exception("Problem preparing mysqli_stmt");
}


/*	Validate login
******************************************
------------------------------------------
*/
public function validateLogin($login) {
	if($this->minLoginLength and mb_strlen($login) < $this->minLoginLength) {
		$this->errors = 141;
		return false;
	}
	if($this->maxLoginLength and mb_strlen($login) > $this->maxLoginLength) {
		$this->errors = 142;
		return false;
	}
	
	if($this->loginAllowedRegex) {
		$legal = preg_match($this->loginAllowedRegex, $login);
		if( $legal === false ) {
			throw new Exception("Error in the regular expression loginAllowedRegex: '{$this->loginAllowedRegex}'");
		}
		if( !$legal ) {
			$this->errors = 143;
			return false;
		}
	}
	
	if($this->loginProhibitedRegex) {
		$illegal = preg_match($this->loginProhibitedRegex, $login);
		if( $illegal === false ) {
			throw new Exception("Error in the regular expression loginProhibitedRegex: '{$this->loginProhibitedRegex}'");
		}
		if( $illegal ) {
			$this->errors = 143;
			return false;
		}
	}
	
	if($this->loginRequiredRegex	) {
		$legal = preg_match($this->loginRequiredRegex, $login);
		if( $legal === false ) {
			throw new Exception("Error in the regular expression loginRequiredRegex: '{$this->loginRequiredRegex}'");
		}
		if( !$legal ) {
			$this->errors = 144;
			return false;
		}
	}
	
	if( strip_tags($login) !== $login ) {
		$this->errors = 143;
		return false;
	}

	$sql = "SELECT\n"
		. "{$this->dbLoginField} FROM {$this->dbUsersTable}\n"
		. "WHERE {$this->dbLoginField} = ?\n"
		. "LIMIT 1";

	if ($stmt = $this->mysqli->prepare( $sql )) {
		$stmt->bind_param('s', $login);
		$stmt->execute();
		$stmt->store_result();

		if ($stmt->num_rows == 1) {
			$this->errors = 145;
			return false;
		}
		return true;
	}
	throw new Exception("Problem preparing mysqli_stmt");
}


/*	Validate password
******************************************
------------------------------------------
*/
public function validatePassword($password) {
	if($this->minPasswordLength and mb_strlen($password) < $this->minPasswordLength) {
		$this->errors = 121;
		return false;
	}
	if($this->maxPasswordLength and mb_strlen($password) > $this->maxPasswordLength) {
		$this->errors = 122;
		return false;
	}
	
	if($this->passwordAllowedRegex) {
		$legal = preg_match($this->passwordAllowedRegex, $password);
		if( $legal === false ) {
			throw new Exception("Error in the regular expression passwordAllowedRegex: '{$this->passwordAllowedRegex}'");
		}
		if( !$legal ) {
			$this->errors = 123;
			return false;
		}
	}
	
	if($this->passwordProhibitedRegex) {
		$illegal = preg_match($this->passwordProhibitedRegex, $password);
		if( $illegal === false ) {
			throw new Exception("Error in the regular expression passwordProhibitedRegex: '{$this->passwordProhibitedRegex}'");
		}
		if( $illegal ) {
			$this->errors = 123;
			return false;
		}
	}
	
	if($this->passwordRequiredRegex	) {
		$legal = preg_match($this->passwordRequiredRegex, $password);
		if( $legal === false ) {
			throw new Exception("Error in the regular expression passwordRequiredRegex: '{$this->passwordRequiredRegex}'");
		}
		if( !$legal ) {
			$this->errors = 124;
			return false;
		}
	}
	return true;
}


}
?>