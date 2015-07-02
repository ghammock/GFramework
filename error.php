<?php

//  Sample error.php file for GFramework usage.
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

include_once 'includes/GF_functions.php';

secure_session_start();

if (isset($_SESSION['error_msg']))
{
    $error = $_SESSION['error_msg'];

    unset($_SESSION['error_msg']);
}

else
    $error = "An unknown error occured.";
?>

<!DOCTYPE html> <!-- HTML 5 -->
<html lang="en-US">
<head>
    <title>An Error Was Encountered</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" type="text/css" href="CSS/style.css">
    <link rel="icon" type="image/x-icon" href="images/favicon.ico">
    
    <!-- Fix for older IE browsers -->
    <!--[if lt IE 9]>
    <script src="http://html5shiv.googlecode.com/svn/trunk/html5.js"></script>
    <![endif]-->
</head>
<body>
  <h1>An error was encountered</h1>
  <p class="error">Details: <?php echo $error; ?></p>
</body>
</html>