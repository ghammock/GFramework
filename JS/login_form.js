/**
 *  File: loginForm.js
 *  Author: Gary Hammock
 *  Date: 2014-11-07
 *
 * ============================================================================
 * REFERENCES
 * ============================================================================
 *
 * http://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL
 *     Retrieved: 2014-11-04.
 *
 * ============================================================================
 * LICENSE (MIT/X11)
 * ============================================================================
 *
 * Copyright (C) 2014 Gary Hammock, PE
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
*/

/**
 *  This function creates a hidden form that is used to POST the SHA-512 value
 *  of the password.  This keeps the client from POST-ing the password as a
 *  plaintext input over the wire.
 *
 *  @param form A handle to the calling form object.
 *  @param password The plaintext password from the <input> attribute.
*/
function hashLoginCredentials(form, password)
{
    // Create a new element input to store the hashed password 
    var hashed_pwd = document.createElement("input");

    // Add the new element to our form. 
    form.appendChild(hashed_pwd);
    hashed_pwd.name = "hashed_pw";
    hashed_pwd.type = "hidden";
    hashed_pwd.value = sha512(password.value);

    // Unset the page form's password attribute value to make sure the
    // plaintext password doesn't get sent.
    password.value = "";

    // With the hashed password stored and the plaintext
    // password blanked, we're ready to submit the form. 
    form.submit();
}
