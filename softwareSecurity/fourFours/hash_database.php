<?
    function pg_connect_db(){
        $dbconn = pg_connect("dbname=fourfours user=ff host=localhost password=adg135sfh246");
        pg_set_client_encoding($dbconn, 'UTF8');
        return $dbconn;
    }

    $dbconn = pg_connect_db();
    $result = pg_prepare($dbconn, "", 'alter table account alter column passwd type character varying(70);');
    $result = pg_execute($dbconn, "", array());
    $result = pg_prepare($dbconn, "", 'SELECT * FROM account');
    $result = pg_execute($dbconn, "", array());
    while ($row = pg_fetch_row($result)) {
        $user = $row[1];
        $password = $row[2];
        # Using the username as salt
        $hashed_password = hash('sha256', $user . $password);
        $result2 = pg_prepare($dbconn, "", "UPDATE account SET passwd='$hashed_password' WHERE username='$user' AND passwd='$password';");
        $result2 = pg_execute($dbconn, "", array());
    }
    echo "done"
?>