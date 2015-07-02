/*
 * File: createDatabase.sql
 * Author: Gary Hammock, PE
 * Date: 2014-10-23
 *
 * Create the website database including:
 *  1.) User Tables,
 *  2.) Audit Log,
 *  3.) Site content,
 *  etc.
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

CREATE DATABASE IF NOT EXISTS `myWebsite`;
USE `myWebsite`;

/*------------------------------------------------------------------------------
|                            CREATE LIMITED USER                               |
------------------------------------------------------------------------------*/

/*
 *  This generates a new user with limited privileges for access through PHP.
*/
CREATE USER 'limited_user'@'localhost' IDENTIFIED BY 'AzBXmWfKwLeR8tqJ';
GRANT SELECT, INSERT, UPDATE, DELETE ON `myWebsite`.*
  TO 'limited_user'@'localhost';

/*------------------------------------------------------------------------------
|                             DATABASE TABLES                                  |
------------------------------------------------------------------------------*/

/*
 *  This table contains the valid user accounts.  These are the individuals
 *  that may access restricted content via a valid credential.
*/
CREATE TABLE IF NOT EXISTS `users`
(
    `user_id`       INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `alias`         VARCHAR(64)  NOT NULL DEFAULT ''      COMMENT 'The user\'s real name or chosen alias',
    `username`      VARCHAR(64)  NOT NULL UNIQUE          COMMENT 'The user\'s chosen username',
    `password`      CHAR(128)    NOT NULL                 COMMENT 'The user\'s shadowed password. Value = hash(hash(password) + salt)',
    `salt`          CHAR(128)    NOT NULL                 COMMENT 'Concatenated with the hashed password to provide authentication',
    `privileges`    VARCHAR(16)  NOT NULL                 COMMENT 'The privilege level that the user has been granted',
    `symmetric_key` CHAR(128)                             COMMENT 'Used for PMs and other low-level encryption (generated by trigger)',
    `email`         VARCHAR(64)  NOT NULL                 COMMENT 'A given user\'s valid email',
    `gender`        CHAR(32)                              COMMENT 'The user\'s gender (if provided)',
    `locale`        VARCHAR(16)  NOT NULL DEFAULT 'en-US' COMMENT 'User content locale (if provided)',
    `joined`        DATETIME                              COMMENT 'The date the user was added to the DB (generated by trigger)',
    `last_logon`    VARCHAR(30)  DEFAULT NULL             COMMENT 'The last time the user logged into the DB',
    `banned`        BOOL         DEFAULT false            COMMENT 'User ban status, true = banned'
)
COMMENT = 'This table contains the valid user accounts.';

/*
 *  This table stores the set of user privileges that are available.
*/
CREATE TABLE IF NOT EXISTS `privilege_levels`
(
    `name` VARCHAR(16) NOT NULL DEFAULT '' COMMENT 'A name associated with the privilege'
)
COMMENT = 'Stores the privilege levels and names that can be assigned to users';

/*
 *  This table contains the access log details for security auditing.
*/
CREATE TABLE IF NOT EXISTS `access_log`
(
    `entry_num`      INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `user_id`        INT UNSIGNED     NULL DEFAULT NULL     COMMENT 'The ID number of the user who attempted to log in (if available)',
    `attempted_name` VARCHAR(64)  NOT NULL DEFAULT ''       COMMENT 'The username submitted for the attempted logon',
    `ip`             VARCHAR(39)  NOT NULL                  COMMENT 'The IP address of the client attempting to login',
    `timestamp`      DATETIME     NOT NULL                  COMMENT 'The timestamp at which the attempt takes place',
    `user_agent`     TEXT             NULL                  COMMENT 'Any data passed by the client as a user agent string',
    `result`         VARCHAR(8)   NOT NULL DEFAULT 'failed' COMMENT 'Stores the login result of the attempt (failed | success)'
)
COMMENT = 'This table contains the access log details for security audits';

/*
 *  This table contains a list of banned user accounts.
*/
CREATE TABLE IF NOT EXISTS `user_blacklist`
(
    `user_id`   INT UNSIGNED NOT NULL               COMMENT 'The ID of the banned user',
    `perma_ban` BOOL         NOT NULL DEFAULT false COMMENT 'A flag for indicating if the user if permanently banned',
    `ban_date`  DATETIME     NOT NULL               COMMENT 'The date of the banning',
    `lift_ban`  DATETIME     NOT NULL               COMMENT 'The date when the ban is to be lifted',
    `reason`    MEDIUMTEXT   NOT NULL               COMMENT 'Specifies the reason the user was banned',
    
    FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`)
        ON DELETE CASCADE ON UPDATE CASCADE
)
COMMENT = 'This table contains a list of banned user accounts';

/*
 *  This table contains a list of white-listed users.  NOTE: White-listed users
 *  should take priority over an IP blacklist.
*/
CREATE TABLE IF NOT EXISTS `user_whitelist`
(
    `user_id`  INT UNSIGNED NOT NULL PRIMARY KEY COMMENT 'The ID of the whitelisted user',
    
    FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`)
        ON DELETE CASCADE ON UPDATE CASCADE
)
COMMENT = 'This table creates a list of \"white-listed\" user accounts that should be able to access the site even if behind a banned IP address';

/*
 *  This table contains a list of banned IP addresses.
*/
CREATE TABLE IF NOT EXISTS `ip_blacklist`
(
    `ip`  VARCHAR(39) NOT NULL PRIMARY KEY COMMENT 'The IP address of a banned client'
)
COMMENT = 'This table contains a list of banned client IPs';

/*
 *  This table stores private messages that are sent between users.
*/
CREATE TABLE IF NOT EXISTS `private_messages`
(
    `message_id`  INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `sender_id`   INT UNSIGNED NOT NULL COMMENT 'The ID number of the sending user',
    `receiver_id` INT UNSIGNED NOT NULL COMMENT 'The ID number of the receiving user',
    `timestamp`   DATETIME     NOT NULL COMMENT 'The date the message was sent',
    `subject`     TINYTEXT     NOT NULL COMMENT 'The subject of the message',
    `read`        BOOL DEFAULT false    COMMENT 'A flag indicating whether the message is read or not',
    `contents`    MEDIUMTEXT   NOT NULL COMMENT 'The message body/contents'
)
COMMENT = 'This table stores private messages (PMs) sent between users';

/*
 *  This table maintains the website page content (e.g. what is served to the
 *  client's browser).
*/
CREATE TABLE IF NOT EXISTS `pages`
(
    `page_id`       INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `title`         VARCHAR(64)  NOT NULL COMMENT 'The title of the webpage',
    `creation_date` DATETIME     NOT NULL COMMENT 'The date the page was created',
    `modified_date` DATETIME     NOT NULL COMMENT 'The date the page was last modified',
    `content` MEDIUMTEXT         NOT NULL COMMENT 'The actual page article, contents, etc.'
)
COMMENT = 'This table stores the contents of each page available on the site (useful to dynamic loading)';

/*
 *  This table stores user comments that are displayed per page.
*/
CREATE TABLE IF NOT EXISTS `comments`
(
    `comment_id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `user_id`    INT UNSIGNED NOT NULL COMMENT 'The ID number of the commenter',
    `page_id`    INT UNSIGNED NOT NULL COMMENT 'The ID of the page on which the comment resides',
    `timestamp`  DATETIME     NOT NULL COMMENT 'The date the message was sent',
    `contents`   MEDIUMTEXT   NOT NULL COMMENT 'The comment body',

    FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`),
    FOREIGN KEY (`page_id`) REFERENCES `pages`(`page_id`) ON DELETE CASCADE
)
COMMENT = 'This table stores user comments that are displayed per page.';

/*
 *  This table maintains uploaded files which may be downloaded by a client.
*/
CREATE TABLE IF NOT EXISTS `files`
(
    `file_id`  INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT 'A unique ID for each file',
    `filename` VARCHAR(255) NOT NULL COMMENT 'The name of the file to be stored',
    `filesize` INT UNSIGNED NOT NULL COMMENT 'The size of the stored file in bytes',
    `filetype` VARCHAR(64)      NULL COMMENT 'The S/MIME type of the file (if given)',
    `path`     TEXT         NOT NULL COMMENT 'The server-path to the location of the file',
    `hash`     CHAR(64)     NOT NULL COMMENT 'The SHA-512 hash of the file (e.g. can be used for de-duplication)'
)
COMMENT = 'This table links files stored on the server to the a handle for up/downloading';

/*
 *  This table links the users with which files they own.
*/
CREATE TABLE IF NOT EXISTS `file_owners`
(
    `user_id` INT UNSIGNED NOT NULL COMMENT 'The ID of the user that owns a given file',
    `file_id` INT UNSIGNED NOT NULL COMMENT 'The ID of the file that is owned by a user',
    
    PRIMARY KEY (`user_id`, `file_id`),
    
    FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (`file_id`) REFERENCES `files` (`file_id`)
        ON DELETE CASCADE ON UPDATE CASCADE
)
COMMENT = 'This relation links the users with which files they own';

/*------------------------------------------------------------------------------
|                                 FUNCTIONS                                    |
------------------------------------------------------------------------------*/

DELIMITER $$

/*
 *  This function will generate a random salt to be used for each user's shadow
 *  password.
*/
CREATE FUNCTION `generateSalt` ()
RETURNS CHAR(128)
BEGIN
    SET @salt := SHA2(RANDOM_BYTES(64), 512);
    
    RETURN @salt;
END $$

/*
 *  This function will generate a random symmetric key for each user for
 *  low-level encryption of DB objects (like PMs).
*/
CREATE FUNCTION `generateSymmetricKey` ()
RETURNS CHAR(128)
BEGIN
    SET @symkey := HEX(RANDOM_BYTES(64));
    
    RETURN @symkey;
END $$

/*
 *  This function will generate a user's shadowed password hash from a given
 *  salt value and a SHA-512 hash of the plaintext password.  NEVER SEND A
 *  PLAINTEXT PASSWORD, have the client hash the password and transmit the hash.
*/
CREATE FUNCTION `createPasswordHash` (`hashedPW` CHAR(128), `salt` CHAR(128))
RETURNS CHAR(128)
BEGIN
    SET @hashcat := CONCAT(`hashedPW`, `salt`);
    SET @pw_hash := SHA2(@hashcat, 512);
    
    RETURN @pw_hash;
END $$

DELIMITER ;

/*------------------------------------------------------------------------------
|                                 TRIGGERS                                     |
------------------------------------------------------------------------------*/

DELIMITER $$

CREATE TRIGGER `access_log_insert_trigger`
BEFORE INSERT ON `access_log`
FOR EACH ROW
BEGIN
    SET NEW.`timestamp` := UTC_TIMESTAMP;
END $$

CREATE TRIGGER `users_insert_trigger`
BEFORE INSERT ON `users`
FOR EACH ROW
BEGIN
    SET NEW.`symmetric_key` := generateSymmetricKey();
    SET NEW.`joined` := UTC_TIMESTAMP;
END $$

CREATE TRIGGER `private_messages_insert_trigger`
BEFORE INSERT ON `private_messages`
FOR EACH ROW
BEGIN
    SET NEW.`timestamp` := UTC_TIMESTAMP;
END $$

CREATE TRIGGER `pages_insert_trigger`
BEFORE INSERT ON `pages`
FOR EACH ROW
BEGIN
    SET NEW.`creation_date` := UTC_TIMESTAMP;
    SET NEW.`modified_date` := UTC_TIMESTAMP;
END $$

CREATE TRIGGER `pages_update_trigger`
BEFORE UPDATE ON `pages`
FOR EACH ROW
BEGIN
    SET NEW.`modified_date` := UTC_TIMESTAMP;
END $$

CREATE TRIGGER `comments_insert_trigger`
BEFORE INSERT ON `comments`
FOR EACH ROW
BEGIN
    SET NEW.`timestamp` := UTC_TIMESTAMP;
END $$

DELIMITER ;

/*------------------------------------------------------------------------------
|                               INITIAL DATA                                   |
------------------------------------------------------------------------------*/

INSERT INTO `privilege_levels` (`name`) VALUES ('Administrator'), ('User');

/*
 *  Now we need to create a system account.
 *
 *  Username: SYSTEM
 *  Random password (not really a valid account, but it's used for
 *  broadcast and global ownership).
*/
SET @sys_salt := generateSalt();
/*SET @sys_pwd := SHA2(CONCAT(SHA2(RANDOM_BYTES(64), 512), @admin_salt), 512);*/
SET @sys_pwd := createPasswordHash(SHA2(RANDOM_BYTES(64), 512), @sys_salt);

/* Insert the admin into the 'users' table. */
INSERT INTO `users`
    (`user_id`, `alias`, `username`, `password`, `salt`,
    `privileges`, `email`, `gender`, `banned`)
VALUES
    (1, 'System', 'SYSTEM', @sys_pwd, @sys_salt,
    'Administrator', 'system@localhost', 'robot', false);

/*
 *  Now we need to create a default administrator account.
 *
 *  Default username: admin
 *  Default password: admin
*/
SET @admin_salt := generateSalt();
/*SET @admin_pwd := SHA2(CONCAT(SHA2('admin', 512), @admin_salt), 512);*/
SET @admin_pwd := createPasswordHash(SHA2('admin', 512), @admin_salt);

/* Insert the admin into the 'users' table. */
INSERT INTO `users`
    (`user_id`, `alias`, `username`, `password`, `salt`,
    `privileges`, `email`, `gender`, `banned`)
VALUES
    (2, 'System Administrator', 'admin', @admin_pwd, @admin_salt,
    'Administrator', 'admin@localhost', 'robot', false);

/* Insert the admin into the list of whitelisted users. */
INSERT INTO `user_whitelist` (`user_id`) VALUES (1), (2);