
# Sitadel - Web Application Security Scanner

```bash
   _   _   _         _____ _                 _       _
  | |_| |_| |      / _____|_)  _            | |     | |
  |         |     ( (____  _ _| |_ _____  __| |_____| |
  |    _    |      \____ \| (_   _|____ |/ _  | ___ | |
  |   |_|   |      _____) ) | | |_/ ___ ( (_| | ____| |
  |         |     (______/|_|  \__)_____|\____|_____)\_) 

```

 ![python3](https://img.shields.io/badge/python-3.6-green.svg) [![Build Status](https://travis-ci.org/shenril/Sitadel.svg?branch=master)](https://travis-ci.org/shenril/Sitadel) ![license](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)

Sitadel is basically an update for WAScan making it compatible for python >= 3.4
It allows more flexibility for you to write new modules and implement new features :

- Frontend framework detection
- Content Delivery Network detection
- Define Risk Level to allow for scans
- Plugin system
- Docker image available to build and run

## Table of Contents

- [Sitadel - Web Application Security Scanner](#sitadel---web-application-security-scanner)
  - [Table of Contents](#table-of-contents)
  - [Requirement Warning](#requirement-warning)
  - [Installation](#installation)
  - [Features](#features)
  - [Usage](#usage)
  - [Modules list](#modules-list)
  - [Examples](#examples)
  - [Run with docker](#run-with-docker)

## Requirement Warning

 This project **ONLY** supports python `>= 3.4`. There will be no backport to 2.7

## Installation

```bash
git clone https://github.com/shenril/Sitadel.git
cd Sitadel
pip3 install .
python sitadel.py --help
```

## Features

- Fingerprints
  - Server
  - Web Frameworks (CakePHP,CherryPy,...)
  - Frontend Frameworks (AngularJS,MeteorJS,VueJS,...)
  - Web Application Firewall (Waf)
  - Content Management System (CMS)
  - Operating System (Linux,Unix,..)
  - Language (PHP,Ruby,...)
  - Cookie Security
  - Content Delivery Networks (CDN)

- Attacks:
  - Bruteforce
    - Admin Interface
    - Common Backdoors
    - Common Backup Directory
    - Common Backup File
    - Common Directory
    - Common File
    - Log File

  - Injection
    - HTML Injection
    - SQL Injection
    - LDAP Injection
    - XPath Injection
    - Cross Site Scripting (XSS)
    - Remote File Inclusion (RFI)
    - PHP Code Injection

  - Other
    - HTTP Allow Methods
    - HTML Object
    - Multiple Index
    - Robots Paths
    - Web Dav
    - Cross Site Tracing (XST)
    - PHPINFO
    - .Listing

  - Vulnerabilities
    - ShellShock
    - Anonymous Cipher (CVE-2007-1858)
    - Crime (SPDY) (CVE-2012-4929)
    - Struts-Shock

## Usage

```bash
sitadel.py [-h] [-r {0,1,2}] [-ua USER_AGENT] [--redirect]
           [--no-redirect] [-t TIMEOUT] [-c COOKIE] [-p PROXY]
           [-f FINGERPRINT [MODULE ...]] [-a ATTACK [MODULE ...]]
           [--config CONFIG] [-v] [--version]
           TARGET_URL
```

| ARGUMENT               | DESCRIPTION                                                                               |
| ---------------------- | ----------------------------------------------------------------------------------------- |
| -h, --help         | Display help |
| -r, --risk {0,1,2}        | Decide the risk level you want Sitadel to run (some attacks won't be executed)          |
| -ua, --user-agent       | User agent used for the HTTP request of the attacks          |
| --redirect      | Indicates to Sitadel to follow the 302 request for page redirection                                          |
| --no-redirect             | Indicates to Sitadel **NOT** to follow the 302 request for page redirection                |
| -t, --timeout                    | Specify the timeout for the HTTP requests to the website                                          |
| -c, --cookie          | Allows to specify the cookie to send with the attack requests                                                              |
| -p, --proxy  | Allows to specify a proxy to perform the HTTP requests               |
| -f, --fingerprint             | Specify the fingerprint modules to activate to scan the website {cdn,cms,framework,frontend,header,lang,server,system,waf} |
| -a, --attack           | Specify the attack modules to activate to scan the website {bruteforce, injection, vulns, other}      |
| -c, --config           | Specify the config file for Sitadel scan, default one is in config/config.yml      |
| -v, --verbosity          | Increase the default verbosity of the logs, for instance: -v , -vv, -vvv                                                      |
| --version          | Show Sitadel version                                                                       |

## Modules list

| FINGERPRINT   | MODULE DESCRIPTION                                                                               |
| ------------- | ----------------------------------------------------------------------------------------- |
| cdn   | Try to guess if the target uses Content Delivery Network (fastly, akamai,cloudflare...) |
| cms        | Try to guess if the target uses a Content Management System (drupal,wordpress,magento...)          |
| framework        | Try to guess if the target uses a backend framework (cakephp, rails, symfony...)          |
| frontend        | Try to guess if the target uses a frontend framework (angularjs, jquery, vuejs...)         |
| header        | Inspect the headers exchanged with the target          |
| lang        | Try to guess the server language used by the target (asp, python, php...)         |
| server        | Try to guess the server technology used by the target (nginx,apache...)          |
| system        | Try to guess the Operation System used by the target (linux,windows...)          |
| waf        | Try to guess if the target uses a Web Application Firewall (barracuda, bigip,paloalto...)          

| ATTACK   | MODULE DESCRIPTION                                                                               |
| ------------- | ----------------------------------------------------------------------------------------- |
| bruteforce   | Try to bruteforce the location of multiple files (backup files, admin consoles...) |
| injection        | Try to perform injection on various language (SQL,html,ldap, javascript...)          |
| vulns        | Try to test for some known vulnerabilities (crime,shellshock)          |
| other        | Try to probe for various interesting resources (DAV, htmlobjects,phpinfo,robots.txt...)          |

## Examples

Simple run

`python3 sitadel http://website.com`

Run with risk level at DANGEROUS and do not follow redirections

`python3 sitadel http://website.com -r 2 --no-redirect`

Run specifics modules only and full verbosity

`python3 sitadel http://website.com -a bruteforce -f header server -v`

## Run with docker

`docker build -t sitadel .`

`docker run sitadel http://example.com`
