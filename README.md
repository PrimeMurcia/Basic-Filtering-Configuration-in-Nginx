# Nginx Security Configuration

## Created By: Prime Murcia

This repository contains an Nginx configuration file `security.conf` designed to enhance the security of your web server by blocking various types of attacks, including SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), and more.

## Steps to Implement

### 1. Create the `security.conf` File

To begin, create a new file named `security.conf` in the Nginx configuration directory:

```bash
sudo nano /etc/nginx/security.conf

2. Add the Configuration
Copy and paste the following configuration into security.conf. This file includes rules to block several types of malicious requests:

SQL Injection (SQLi)
Cross-Site Scripting (XSS)
Remote Code Execution (RCE)
XML External Entity (XXE) Attacks
Insecure HTTP Methods
Deserialization Attacks
3. Include security.conf in Nginx
To activate the configuration, add the following line to your nginx.conf or in a specific site configuration file located in /etc/nginx/sites-available/:

nginx
Copy code
include /etc/nginx/security.conf;
4. Block SQL Injections
