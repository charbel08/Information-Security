<?
        session_start(); 

	###################################################################################################
	# https://www.owasp.org/index.php/Top_10_2013-Top_10
	###################################################################################################

	###################################################################################################
	# FIX OWASP A8: CSRF (Cross Site Request Forgery)
	# First verify that this is vulnerable. That is, if attacker gets target to follow a malicious
	# URL, the attacker can get the user to perform an operation they had not intended.
	# For example, craft a URL that gets the target to delete one of their entries.
	# Fix this by creating a random page token. The page token is placed in the 
	# session. Now every reply to a page, includes the page token, in the URL, as a hidden variable etc.
	# Before processing a request, first verify the page token.
	###################################################################################################

	if(!isset($_SESSION['isLoggedIn']))$_SESSION['isLoggedIn']=False;

	# Verifying the token (CSRF Fix)
	# Checking that token check happens when a user is logged in to avoid blocking the login screen with the exception
	if(count($_GET) + count($_POST) > 0 && $_SESSION['isLoggedIn']){
		if(!isset($_REQUEST['token'])){
			throw new Exception('Token not found');
		}
		elseif(strcmp($_REQUEST['token'], $_SESSION['token']) <> 0){
			throw new Exception('No token match');
		}
	}
	$operation=$_REQUEST['operation'];
	$g_debug="";
	$g_errors="";

	# Setting up HTTPS (Sensitive Data Exposure Fix)
	if (!isset($_SERVER['HTTPS'])) {
		header('Location: https://' . $_SERVER["SERVER_NAME"] . $_SERVER['REQUEST_URI']);
	}

	// overridden database functions
        function pg_connect_db(){

		###################################################################################################
		# FIX OWASP A6: SENSITIVE DATA EXPOSURE
		# Take a look at the db, whats wrong with the passwords?
		# Fix by hashing passwords, as well, you need to fix authentication to check hashes
		# Additionally, the application is not using https to communicate, fix this
		###################################################################################################
				
                $dbconn = pg_connect("dbname=fourfours user=ff host=localhost password=adg135sfh246");
                pg_set_client_encoding($dbconn, 'UTF8');
                return $dbconn;
        }
	if($operation == "login"){

		# Sanitizing input (XSS Fix)
		$user=htmlentities($_REQUEST['user'], ENT_QUOTES, 'UTF-8');

		# Hashing password to find look up it's hashed value in database (Sensitive Data Exposure Fix)
		$password = hash('sha256', $user . htmlentities($_REQUEST['password'], ENT_QUOTES, 'UTF-8'));
		$dbconn = pg_connect_db();

		# FIX OWASP 2013 A1: SQL Injection, use prepared statements
		# Using prepared statements (SQL Injection Fix)
		$query= "SELECT id, username, firstName, lastName, passwd FROM account WHERE username=$1 AND passwd=$2";
		$result = pg_prepare($dbconn, "statement1", $query);
		$result = pg_execute($dbconn, "statement1", array($user, $password));
		if($row = pg_fetch_row($result)) {

			###################################################################################################
			# FIX OWASP 2013 A2: SESSION FIXATION
			# Check that this application is vulnerable by bringing up firefox developer tools,
			# visiting the website, then logging in, notice that the same cookie is used after
			# change of privilege.
			# Fix this by...
			# Destroy current session and get a new session id when change in privilege.
			# Check to make sure that the cookie changes when logged in
			# Note: Some browsers now protect against reflection attacks, but not all.
			# See: http://php.net/manual/en/function.session-regenerate-id.php
			###################################################################################################

			# Sanitizing inputs (XSS Fix)
			$_SESSION['accountId']=htmlentities($row[0], ENT_QUOTES, 'UTF-8');
			$_SESSION['user']=htmlentities($row[1], ENT_QUOTES, 'UTF-8');
			$_SESSION['firstName']=htmlentities($row[2], ENT_QUOTES, 'UTF-8');
			$_SESSION['lastName']=htmlentities($row[3], ENT_QUOTES, 'UTF-8');
			$_SESSION['isLoggedIn']=True;

			# Creating a random token and using username as salt (CSRF Fix)
			$_SESSION['token'] = hash('sha256', $user . uniqid(rand(), true));

			# Creating hash map to store our indirect references and storing them in cookies (IDOR Fix)
			$hash_map = array();
			$result = pg_prepare($dbconn, "", "SELECT * FROM solution WHERE accountid=$1");
			$result = pg_execute($dbconn, "", array($row[0]));
			while ($row = pg_fetch_row($result)) {
				$hash_map[hash('sha256', "saltexpression" . $row[0])] = $row[0];
			}
			$_SESSION['expressionMap']=$hash_map;

			# Destroying the old session and creating a new one (Session Fixation Fix)
			session_regenerate_id(True);
		} else {
			$g_debug = "$user not logged in";
			$_SESSION['isLoggedIn']=False;
		}
	} elseif($operation == "deleteExpression"){

		# Sanitizing input (XSS Fix) and getting the un-hashed version of expressionId (IDOR Fix)
		$expressionId = $_SESSION['expressionMap'][htmlentities($_REQUEST['expressionId'], ENT_QUOTES, 'UTF-8')];
		$dbconn = pg_connect_db();

		###################################################################################################
		# FIX OWASP 2013 A4: INSECURE DIRECT OBJECT REFERENCES
		# Prove that it is vulnerable by logging in as one user and deleting another users entry
		# Fix this by...
		# Either fix the insecure part, that is, verify that the user can perform the operation
		# of the direct object reference part, that is, fix the id's so they don't directly 
		# reference the expressionId, or both (even better).
		# Another problem: why get account id from the request? In this case, this is part of the 
		# insecure direct object reference, that is, referencing the account id.
		# Note: Simply not giving the user interface the option to delete is not sufficient.
		###################################################################################################

		# Using prepared statements (SQL Injection Fix) and accountId is now taken from the session instead of the request (IDOR Fix)
		$result = pg_prepare($dbconn, "statement2", 'DELETE FROM solution WHERE id=$1 AND accountId=$2;');
		$result = pg_execute($dbconn, "statement2", array($expressionId, $_SESSION['accountId']));

		# Removing expressionId from expression map (IDOR Fix)
		unset($_SESSION['expressionMap'][htmlentities($_REQUEST['expressionId'], ENT_QUOTES, 'UTF-8')]);
	} elseif($operation == "addExpression"){

		###################################################################################################
		# FIX: XSS: user input/output is not vetted
		# First check that the application is vulnerable by placing html in the
		# database and then viewing the HTML as it exits the db
		# Fix this by ...
		# Either whitelisting the input, or escape the input
		# Do the same for all untrusted input and output!
		# http://stackoverflow.com/questions/46483/htmlentities-vs-htmlspecialchars
		###################################################################################################

		# Sanitizing input (XSS Fix)
		$expression = htmlentities($_REQUEST['expression'], ENT_QUOTES, 'UTF-8');
		$value=htmlentities($_REQUEST['value'], ENT_QUOTES, 'UTF-8');

		# accountId is now taken from the session instead of the request (IDOR Fix)
		$accountId=$_SESSION['accountId'];

		$dbconn = pg_connect_db();

		# Using prepared statements (SQL Injection Fix)
		$result = pg_prepare($dbconn, "statement3", 'SELECT * FROM solution WHERE expression=$1;');
		$result = pg_execute($dbconn, "statement3", array($expression));

		if(!($row = pg_fetch_row($result))) {

			# Using prepared statements (SQL Injection Fix)
			$result = pg_prepare($dbconn, "statement4", 'insert into solution (value, expression, accountId) values ($1, $2, $3);');
			$result = pg_execute($dbconn, "statement4", array($value, $expression, $accountId));

			# Getting the expression ID and adding it to the expression map in the session (IDOR Fix)
			$result = pg_prepare($dbconn, "statement5", 'SELECT id FROM solution WHERE value=$1 AND expression=$2 AND accountId=$3;');
			$result = pg_execute($dbconn, "statement5", array($value, $expression, $accountId));
			$row = pg_fetch_row($result);
			$_SESSION['expressionMap'][hash('sha256', "saltexpression" . $row[0])] = $row[0];
		} else {
			$g_errors="$expression is already in our database";
		}
	} elseif($operation == "logout"){
		unset($_SESSION);
		$_SESSION['isLoggedIn']=False;
		session_destroy();
	}
	$g_isLoggedIn=$_SESSION['isLoggedIn']; 
	$g_index="";
	for($i=0;$i<=100;$i+=10){ $g_index=$g_index . "<a href=#$i>$i</a> "; } 
	$g_userFullName=$_SESSION['firstName'] . " " . $_SESSION['lastName'];
	$g_userFirstName=$_SESSION['firstName'];
	$g_accountId=$_SESSION['accountId'];
?>
<html>
	<body>
		<center>
		<h1>Four Fours</h1>
		<font color="red"><?=$g_errors ?></font><br/><br/>
		<? if($g_isLoggedIn){ ?>
			<!-- Adding the token to the logout request (CSRF Fix)-->
			<a href=?operation=logout&token=<?php echo $_SESSION['token']?>>Logout</a>
			<br/>
			<br/>
			<div style="width:400px; text-align:left;">
			Welcome <?= $g_userFirstName ?>. 
			Using only four 4s' and the operations +,-,*,/,^ (=exponentiation) and sqrt (=square root)
			create as many of the values below as you can. For example, for 2, I have ((4/4)+(4/4)), for 16, I have sqrt(4*4*4*4).
			</div>
			<br/>
			<table>
				<tr>
					<th>value</th><th>expression and author</th>
				</tr>
				<?php
				for($i=0;$i<=100;$i++){ 
					if($i%10==0){ ?>
						<td align="center" colspan="2" style="border-bottom:2pt solid black;"><?=$g_index ?></td>
					<? } ?>

					<tr> 
						<td valign="top" style="border-bottom:2pt solid black;"> <a name="<?=$i?>" ><?=$i ?></a></td>
						<td valign="top" style="border-bottom:2pt solid black;">
							<table>
								<?php
									$dbconn = pg_connect_db();
									$result = pg_prepare($dbconn, "", "SELECT firstName, lastName, value, expression, s.accountId, s.id FROM account a, solution s WHERE a.id=s.accountId AND value=$1 ORDER BY firstName, lastName, expression");
									$result = pg_execute($dbconn, "", array($i));
									# FIX XSS: Output from users must be whitelisted or escaped
									# Getting the random token from the session (CSRF Fix)
									$rt = $_SESSION['token'];

									while ($row = pg_fetch_row($result)) {
										$count=0;
										# Sanitizing output (XSS Fix)
										$firstName=htmlentities($row[$count++], ENT_QUOTES, 'UTF-8');
										$lastName=htmlentities($row[$count++], ENT_QUOTES, 'UTF-8');
										$value=htmlentities($row[$count++], ENT_QUOTES, 'UTF-8');
										$expression=htmlentities($row[$count++], ENT_QUOTES, 'UTF-8');
										$expressionAccountId=htmlentities($row[$count++], ENT_QUOTES, 'UTF-8');
										$expressionId=htmlentities($row[$count++], ENT_QUOTES, 'UTF-8');
										if($expressionAccountId==$g_accountId){

											# Hashing the expressionId (IDOR Fix)
											$expressionId = hash('sha256', "saltexpression" . $expressionId);

											# Adding the token to the GET request (CSRF Fix) and removing accountId field (IDOR Fix)
											$deleteLink="<a href=\"?operation=deleteExpression&expressionId=$expressionId&token=$rt\"><img src=\"delete.png\" width=\"20\" border=\"0\" /></a>";
										} else {
											$deleteLink="";
										}
										echo("<tr> <td>$expression</td><td>$deleteLink</td><td>$firstName $lastName</td></tr>");
									}
								?>
								<tr> 
									<form method="post">
										<td><input type="text" name="expression"/> </td>
										<td><input type="submit" value="add"/></td>
										<!-- Adding the token to the addExpression request (CSRF Fix)-->
										<input type="hidden" name="token" value="<?= $_SESSION['token']; ?>">
										<input type="hidden" name="value" value="<?=$i?>"/>
										<input type="hidden" name="operation" value="addExpression"/>
										<!-- Removed accountId (IDOR Fix)-->
									</form>
								</tr>
							</table>
						</td>
					</tr>
				<? } ?>
			</table>
		<? } else { ?>
			<form method="post">
				<table>
					<tr>
						<td>user name: <input type="text" size="10" name="user"/></td>
						<td>password: <input type="password" size="10" name="password"/> </td>
						<td>
							<input type="hidden" name="operation" value="login"/>
							<input type="submit" value="login"/>
						</td>
					</tr>
					<tr>
						<td colspan="3"><?php echo($g_debug); ?></td>
					</tr>
				</table>
			</form>
		<? } ?>
		</center>
	</body>
</html>
