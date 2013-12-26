SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";

DROP TABLE IF EXISTS auth_codes;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS access_tokens;
DROP TABLE IF EXISTS refresh_tokens;

CREATE TABLE `auth_codes` (
    `code` varchar(40) NOT NULL,
    `client_id` varchar(20) NOT NULL,
    `user_id` varchar(20) NOT NULL,
    `redirect_uri` varchar(200) NOT NULL,
    `expires` int(11) NOT NULL,
    `scope` varchar(250) DEFAULT NULL,
    PRIMARY KEY (`code`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `clients` (
    `client_id` varchar(20) NOT NULL,
    `client_secret` varchar(200) NOT NULL,
    `redirect_uri` varchar(200) NOT NULL,
    PRIMARY KEY (`client_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `access_tokens` (
    `oauth_token` varchar(40) NOT NULL,
    `client_id` varchar(20) NOT NULL,
    `user_id` int(11) UNSIGNED NOT NULL,
    `expires` int(11) NOT NULL,
    `scope` varchar(200) DEFAULT NULL,
    PRIMARY KEY (`oauth_token`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

CREATE TABLE `refresh_tokens` (
    `oauth_token` varchar(40) NOT NULL,
    `refresh_token` varchar(40) NOT NULL,
    `client_id` varchar(20) NOT NULL,
    `user_id` int(11) UNSIGNED NOT NULL,
    `expires` int(11) NOT NULL,
    `scope` varchar(200) DEFAULT NULL,
    PRIMARY KEY (`oauth_token`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
