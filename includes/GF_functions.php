<?php

//  PHP Functions for GFramework
//
//  Author: Gary Hammock, PE
//  Date: 2013-10-25
//
//  =========================License: (MIT/X11)=================================
//  Copyright (C) 2014 Gary Hammock
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//  
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.

include_once 'GF_config.php';

/**
 *  This function generates a secure PHP session.  It should be called in the
 *  header of all PHP pages on the site.
*/
function secure_session_start()
{
    $session_name = 'secure_session_id';
    $ssl_secure = SSL_SECURE;

    // This keeps JavaScript from being able to access the session id.
    // (Prevents XSS attacks).
    $httponly = true;

    // Forces sessions to only use cookies.
    if (ini_set('session.use_only_cookies', 1) === FALSE)
        throwError("Could not initiate a secure session");

    // Get the current cookies settings.
    $cookieParams = session_get_cookie_params();

    // Set the appropriate lifetime of the cookie.
    // To use the default, initialize this value to $cookieParams["lifetime"].
    $cookieLifetime = $cookieParams["lifetime"];

    session_set_cookie_params( $cookieParams["lifetime"],
                               $cookieParams["path"],
                               $cookieParams["domain"],
                               $ssl_secure,
                               $httponly);

    // Sets the session name to the one set above.
    session_name($session_name);
    session_start();  // Starts the "safe" PHP session.
    session_regenerate_id();  // Regenerates the session, deletes the old one.

}  // End function secure_session_start().

/**
 *  This function processes a login request by comparing a username and hashed
 *  password to what is stored in the database.
 *
 *  Param: $username The attempted login name of the user.
 *  Param: $password An SHA-512 hash of the entered password.
 *  Param: $mysqli The database connection of the session.
 *
 *  Returns: True if the login is valid, false otherwise.
*/
function login ($username, $password, $mysqli)
{
    $ip           = $_SERVER['REMOTE_ADDR'];
    $user_agent   = $_SERVER['HTTP_USER_AGENT'];
    $result       = 'Failed';

    $query = "SELECT `user_id`, `alias`, `password`, `salt`, " .
             "       `last_logon`, `banned` " .
             "FROM `users` " .
             "WHERE `username` = ? " .
             "LIMIT 1";

    $query = $mysqli->prepare($query);
    $query->bind_param('s', $username);
    $query->execute();
    $query->store_result();

    // If the query returns a result, the user exists in the database.
    if ($query->num_rows == 1)
    {
        $query->bind_result($user_id, $alias, $hashed_pw, $salt,
                            $lastlogon, $banned);
        $query->fetch();

        // Check for brute force attempts and lock the account.
        if (bruteForceAttempt($user_id, $mysqli) == true)
            return false;

        // Check that the user isn't banned.
        if ($banned != false)
            throwError("You have been banned");

        // Hash the password with the salt to check credentials.
        $password = hash('sha512', $password . $salt);

        // We need to check if the submitted password equals
        // the one stored in the database.
        if ($hashed_pw == $password)
        {
            $user_id = preg_replace("/[^0-9]+/", "", $user_id);
            $_SESSION['user_id'] = $user_id;

            $username = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $username);
            $_SESSION['username'] = $username;

            $alias = preg_replace("/[^a-zA-Z0-9_\-\ ]+/", "", $alias);
            $_SESSION['alias'] = $alias;

            // This string is used to uniquely identify the login session.
            $_SESSION['login_string'] = hash('sha512', $salt . $user_agent);

            $_SESSION['last_logon'] = $lastlogon;

            // Update the last log-on time.
            $query = "UPDATE `users` SET `last_logon` = UTC_TIMESTAMP " .
                     "WHERE `user_id` = ?";
            $query = $mysqli->prepare($query);
            $query->bind_param('i', $user_id);
            $query->execute();

            // Login successful!
            $result = 'Success';

        }  // End password matching.

    }  // End if-statement checking for returned number of users.

    $log_query = "INSERT INTO `access_log` " .
                 "(`user_id`, `attempted_name`, `ip`, `timestamp`, " .
                 "`user_agent`, `result`) " .
                 "VALUES (?, ?, ?, UTC_TIMESTAMP, ?, ?)";
    $log_query = $mysqli->prepare($log_query);
    $log_query->bind_param('issss', $user_id, $username, $ip,
                           $user_agent, $result);
    $log_query->execute();

    if ($result == 'Success')
        return true;
    else
        return false;

}  // End function login().

/**
 *  This function handles the user logout.  It deletes the session variables
 *  and the cookie before destroying the PHP session.
*/
function logout ()
{
    // Unset/clear the session variables.
    $_SESSION = array();

    // Get the cookie parameters.
    $cookieParams = session_get_cookie_params();

    // The cookie expiry time in epochtime units.
    // To expire the cookie, we set it to a date in the past.
    // time() - 3600 would work, but the ultimate expiry is:
    $expire = 1;

    // Delete the actual cookie.
    setcookie(session_name(),
              '',                      // The cookie name
              $expire,                 // The expiry time
              $cookieParams["path"],   // The valid paths for the cookie
              $cookieParams["domain"],
              $cookieParams["secure"],
              $cookieParams["httponly"]);

    // Destroy the session and return to the home page.
    session_destroy();
    header('Location: ' . BASE_URL . 'index.php?logout=true');
    exit();

}  // End function logout().

/**
 *  This function queries the access log to check for possible
 *  brute forcing of accounts.
 *
 *  Param: $user_id The ID number of a valid user.
 *  Param: $mysqli The database connection of the session.
 *
 *  Returns: True if there is a possible brute force attack, false otherwise.
*/
function bruteForceAttempt ($user_id, $mysqli)
{
    // Determine the time window to check for brute force attempts.
    $query = "SELECT DATE_SUB(UTC_TIMESTAMP, INTERVAL " .
              LOCKOUT_WINDOW . " SECOND)";
    $query = $mysqli->prepare($query);
    $query->execute();
    $query->store_result();
    $query->bind_result($window);
    $query->fetch();

    $query = "SELECT COUNT(*) FROM `access_log` " .
             "WHERE `user_id` = ? AND `timestamp` > ?";
    $query = $mysqli->prepare($query);
    $query->bind_param('is', $user_id, $window);
    $query->execute();
    $query->store_result();
    $query->fetch();

    // If there have been more than 5 failed logins,
    // assume this is a brute force attempt.
    if ($query->num_rows >= FAILED_LOGINS)
        return true;
    else
        return false;

}  // End function bruteForceAttempt().

/**
 *  This function checks that a user is still currently logged in
 *  (as opposed to simply hitting the "back" button after a log-out).
 *
 *  Param: $mysqli The database connection of the session.
 *
 *  Returns: True if the user is still logged in, false otherwise.
*/
function isLoggedIn ($mysqli)
{
    // Check that all the session variables are set.
    if (isset($_SESSION['user_id'],
              $_SESSION['username'],
              $_SESSION['login_string']))
    {
        $user_id      = $_SESSION['user_id'];
        $username     = $_SESSION['username'];
        $login_string = $_SESSION['login_string'];

        $user_agent   = $_SERVER['HTTP_USER_AGENT'];

        $query = "SELECT `password` FROM `users` " .
                 "WHERE `user_id` = ? LIMIT 1";

        $query = $mysqli->prepare($query);
        $query->bind_param('i', $user_id);
        $query->execute();
        $query->store_result();

        if ($query->num_rows == 1)
        {
            $query->bind_result($password);
            $query->fetch();
            $login_check = hash('sha512', $salt . $user_agent);

            // The user is logged in.
            if ($login_check == $login_string)
                return true;

            // The user is not logged in.
            else
                return false;
        }  // End if-statement (num_rows == 1).

        // No results were returned.
        else
            return false;

    }  // End if(isset()).
    
    // No session variables are set.  User is not logged in.
    else
        return false;
    
}  // End function login_check().

/**
 *  This function sends a message to the error page and retrieves
 *  it for the client.
 *
 *  Param: $message The data to report to the client
 *
 *  Returns: none.
*/
function throwError ($message)
{
    $_SESSION['error_msg'] = $message;
    header('Location: ' . BASE_URL . 'error.php');
    exit();

}  // End function throwError().

/**
 *  Ensure that a given URL is sanitized to prevent Cross-Site
 *  Scripting (XSS) attacks and Click-Jacking.
 *
 *  Param: $url The Uniform Resource Locator (URL) string to escape.
 *
 *  Returns: The escaped/sanitized URL as a string.
*/
function escapeURL ($url)
{
    // Make sure the URL is a string.
    $url = (string)$url;

    if ($url == '')
        return $url;

    $url = preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\\x80-\\xff]|i',
                        '',
                        $url);

    // Strip off any non-printables.
    filter_var($url, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW);

    $url = htmlentities($url, ENT_QUOTES);
    $url = str_replace('&amp;', '&#038;', $url);

    return $url;

}  // End function escapeURL().

/**
 *  This function converts a given timestamp to a string containing a more
 *  "human-readable" format
 *
 *  Param: $date A time stamp (in epochtime) that is to be converted.
 *
 *  Returns: A string containing the elasped (or future) time
 *           (e.g. 10 minutes ago).
*/
function convertToReadableTime ($date)
{
    if ($date == 0)
        return "right now";

    // Store an array of time period strings.
    $time_periods = array("second",
                          "minute",
                          "hour",
                          "day",
                          "week",
                          "month",
                          "year",
                          "decade");

    // We'll use the conversions to go from the epoch time to
    // a "human-readable" approximation.
    $time_conversions = array("60",    // Seconds-per-Minute.
                              "60",    // Minutes-per-Hour.
                              "24",    // Hours-per-Day.
                              "7",     // Days-per-Week.
                              "4.35",  // Weeks-per-Month.
                              "12",    // Months-per-Year.
                              "10");   // Years-per-decade.

    $now = time();  // Get the current time.

    // Determine if the given date occurs in the future or the past.
    if ($now > $date)
    {
        $difference = $now - $date;
        $tense = "ago";
    }
    else
    {
        $difference = $date - $now;
        $tense = "from now";
    }

    // Convert the time difference from seconds to the largest available
    // integer time period.  For example 7200 seconds becomes 2 hours, but
    // not 0.08 days.
    for ($j = 0;
           ($difference >= $time_conversions[$j])
        && ($j < count($time_conversions) - 1);
        $j++)
    {
        $difference /= $time_conversions[$j];
    }

    $difference = round($difference);

    // If the calculated difference is greater than 1, pluralize the tense.
    if ($difference != 1)
        $time_periods[$j] .= "s";

    // Return the "nice time" as a string.
    // For example: "10 minutes ago", "24 days from now".
    return "$difference $time_periods[$j] {$tense}";

}  // End function convertToReadableTime().

// EoF functions.php.
?>