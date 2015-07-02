<?php

//  Configuration file for GFrameWork
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

define("BASE_URL", "http://localhost/GFramework/");

define("DB_HOST",     "localhost");         // The name of the server.
define("DB_USER",     "limited_user");      // The login username.
define("DB_PASSWORD", "AzBXmWfKwLeR8tqJ");  // The login password.
define("DATABASE",    "myWebsite");         // The database name.

// If SSL certificates are available, set the following to TRUE.
define("SSL_SECURE", FALSE);

// Sets the maximum number of failed login attempts before triggering the
// brute force lockout (default = 5).
define("FAILED_LOGINS", 5);

// Sets the window (in seconds) to consider brute forcing (i.e. if a user
// exceeds FAILED_LOGINS in the specified window, lock the account).
// The default is 2 hours (7200 s).
define("LOCKOUT_WINDOW", (2 * 60 * 60));

?>