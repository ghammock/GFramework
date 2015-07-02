<?php

//  This file processes the POST parameters for logons.
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

include_once 'connect_to_DB.php';
include_once 'GF_functions.php';

secure_session_start();

/*
 *  NOTE: Only post the hashed password, NEVER POST A PLAINTEXT PASSWORD!
*/

if (isset($_POST['username'], $_POST['hashed_pw']))
{
    $username = $_POST['username'];
    $password = $_POST['hashed_pw'];    // This should be the hashed password!
    
    // On successful login, go to the protected page.
    if (login($username, $password, $mysqli) == true)
    {
        header('Location: ' . BASE_URL . 'index.php');
        exit();
    }
    
    // Show an error on a failed login.
    else
    {
        header('Location: ' . BASE_URL . 'index.php?badlogon');
        exit();
    }
}

else
    throwError("Could not process your logon request.");

?>