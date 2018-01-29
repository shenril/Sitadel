# Linguini - Web Application Security Scanner
 ![python3](https://img.shields.io/badge/python-3.6-green.svg) [![Build Status](https://travis-ci.org/shenril/Linguini.svg?branch=master)](https://travis-ci.org/shenril/Linguini) ![license](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)

Linguini is inspired by [Spaghetti](https://github.com/m4ll0k/Spaghetti)


Linguini is basically an update for Spaghetti making it compatible for python >= 3.4
It also makes the scans more flexible and allows to create your own modules quite simply

## Installation
```
$ git clone https://github.com/shenril/Linguini.git
$ cd Linguini
$ python setup.py install
$ python linguini.py --help
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


## Example
Simple run

`python linguini website.com `

Run with risk level at DANGEROUS and do not follow redirections

`python linguini website.com -r 2 --no-redirect`

Run specifics modules only and full verbosity

`python linguini website.com -a admin backdoor -f header server -vvv`

## Run with docker
`docker build -t linguini .`

`docker run linguini http://example.com`

## Credits
A big thanks to Momo Outaadi(M4ll0k) for sharing his project [Spaghetti](https://github.com/m4ll0k/Spaghetti)

