<?php

//  Database connection file for GFramework
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

// Attempt to connect to the MySQL database using the data provided
// in "GF_config.php"
$mysqli = new mysqli(DB_HOST,      // The server housing the database.
                     DB_USER,      // The name of the limited user with access.
                     DB_PASSWORD,  // The limited user's password.
                     DATABASE);    // The name of the database to interface.

// Ensure that the connection was successful, otherwise, throw an error.
if ($mysqli->connect_error)
{
    $msg = "Unable to connect to MySQL Database";
    
    header('Location: ' . BASE_URL . 'error.php?err=Unable to connect to MySQL Database');
    exit();
}

// EoF connect_to_DB.php.
?>