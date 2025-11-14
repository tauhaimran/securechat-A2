# run these ONCE ONLY
CREATE DATABASE securechat;

CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
###################################

#this shows my databases
SHOW DATABASES;

#this shows all sql users
SELECT user, host FROM mysql.user;

#this shows priveliges of users
SHOW GRANTS FOR 'scuser'@'localhost';

#this shows all the tables made ( after executing db.py )
USE securechat;
SHOW TABLES;
DESCRIBE users;

#view registered users
SELECT id, username, HEX(salt) AS salt_hex, pwd_hash FROM users;

#view all users
USE securechat;
SELECT * FROM users;


#use this to delete the table when testing from scratch again
USE securechat;
DELETE FROM users;
drop table users;


