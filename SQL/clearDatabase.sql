/*
 * File: clearDatabase.sql
 * Author: Gary Hammock, PE
 * Date: 2014-10-23
 *
 * Drops all tables from the specified database and drops the database.  This is
 * for the "Nuke-and-Repave" option.
 *
 * =========================License: (MIT/X11)=================================
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

USE `myWebsite`;

DROP TRIGGER IF EXISTS `access_log_insert_trigger`;
DROP TRIGGER IF EXISTS `users_insert_trigger`;
DROP TRIGGER IF EXISTS `private_messages_insert_trigger`;
DROP TRIGGER IF EXISTS `pages_insert_trigger`;
DROP TRIGGER IF EXISTS `pages_update_trigger`;
DROP TRIGGER IF EXISTS `comments_insert_trigger`;

DROP FUNCTION IF EXISTS `generateSalt`;
DROP FUNCTION IF EXISTS `generateSymmetricKey`;
DROP FUNCTION IF EXISTS `createPasswordHash`;

DROP TABLE IF EXISTS `privilege_levels`;
DROP TABLE IF EXISTS `access_log`;
DROP TABLE IF EXISTS `user_blacklist`;
DROP TABLE IF EXISTS `user_whitelist`;
DROP TABLE IF EXISTS `ip_blacklist`;
DROP TABLE IF EXISTS `private_messages`;
DROP TABLE IF EXISTS `comments`;
DROP TABLE IF EXISTS `file_owners`;
DROP TABLE IF EXISTS `files`;

DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `pages`;

DROP DATABASE IF EXISTS `myWebsite`;

/*
 *  Since there is no "IF EXISTS" with "DROP USER", we'll give the limited user
 *  a low-level, benign privilege to ensure that user exists.  Then, we'll drop
 *  the user.
*/
GRANT USAGE ON *.* TO 'limited_user'@'localhost';
DROP USER 'limited_user'@'localhost';