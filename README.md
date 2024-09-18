# Nginx Security Configuration

## Created By: Prime Murcia

This repository contains an Nginx configuration file `security.conf` designed to enhance the security of your web server by blocking various types of attacks, including SQL Injection (SQLi), Cross-Site Scripting (XSS), Remote Code Execution (RCE), and more.

## Steps to Implement

### 1. Create the `security.conf` File

To begin, create a new file named `security.conf` in the Nginx configuration directory:

```bash
sudo nano /etc/nginx/security.conf
```

### 2. Add the Configuration

Copy and paste the following configuration into security.conf. This file includes rules to block several types of malicious requests:

#####  Cross-Site Scripting (XSS)
#####  Remote Code Execution (RCE)
#####  XML External Entity (XXE) Attacks
#####  Insecure HTTP Methods

```bash
## Created By Prime Murcia

## create file security.conf
## nano /etc/nginx/security.conf
## add in nginx.conf or in sites-available
## include /etc/nginx/security.conf

## Block SQL Injections
set $block_sql_injections 0;

if ($query_string ~* "union.*select.*\(") {
    set $block_sql_injections 1;
}

if ($query_string ~* "union.*all.*select.*") {
    set $block_sql_injections 1;
}

if ($query_string ~* "select.*from.*information_schema.tables") {
    set $block_sql_injections 1;
}

if ($query_string ~* "select.*from.*mysql.*user") {
    set $block_sql_injections 1;
}

if ($query_string ~* "concat.*\(") {
    set $block_sql_injections 1;
}

if ($query_string ~* "union.*select.*from") {
    set $block_sql_injections 1;
}

if ($query_string ~* "sleep\(") {
    set $block_sql_injections 1;
}

if ($block_sql_injections = 1) {
    return 403;
}

## Block XSS (Cross-Site Scripting)
set $block_xss 0;

if ($query_string ~* "<script>") {
    set $block_xss 1;
}

if ($query_string ~* "%3Cscript%3E") {
    set $block_xss 1;
}

if ($query_string ~* "javascript:") {
    set $block_xss 1;
}

if ($query_string ~* "data:text/html") {
    set $block_xss 1;
}

if ($query_string ~* "onmouseover=") {
    set $block_xss 1;
}

if ($query_string ~* "onload=") {
    set $block_xss 1;
}

if ($query_string ~* "document.cookie") {
    set $block_xss 1;
}

if ($block_xss = 1) {
    return 403;
}

## Block RCE (Remote Code Execution)
set $block_rce 0;

if ($query_string ~* "system\(") {
    set $block_rce 1;
}

if ($query_string ~* "exec\(") {
    set $block_rce 1;
}

if ($query_string ~* "shell_exec\(") {
    set $block_rce 1;
}

if ($query_string ~* "passthru\(") {
    set $block_rce 1;
}

if ($query_string ~* "eval\(") {
    set $block_rce 1;
}

if ($query_string ~* "proc_open\(") {
    set $block_rce 1;
}

if ($query_string ~* "assert\(") {
    set $block_rce 1;
}

if ($block_rce = 1) {
    return 403;
}

## Block XXE (XML External Entities)
set $block_xxe 0;

if ($query_string ~* "<!DOCTYPE\s+[^>]*\s+SYSTEM\s+") {
    set $block_xxe 1;
}

if ($query_string ~* "<!ENTITY\s+[^>]*\s+SYSTEM\s+") {
    set $block_xxe 1;
}

if ($query_string ~* "<!ENTITY\s+[^>]*\s+PUBLIC\s+") {
    set $block_xxe 1;
}

if ($block_xxe = 1) {
    return 403;
}

## Block Broken Authentication
# You should implement proper authentication mechanisms in your application.
# Example: Ensure strong passwords and multi-factor authentication.

## Block Sensitive Data Exposure
# Use SSL/TLS to encrypt data in transit
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;

# Block insecure HTTP methods
if ($request_method ~* ^(TRACE|TRACK|DELETE|OPTIONS)) {
    return 405;
}

## Block Security Misconfiguration
# Disable directory listing
autoindex off;

# Disable server tokens to prevent leaking version info
server_tokens off;

## Block Insecure Deserialization
set $block_deserialization 0;

if ($query_string ~* "O:.*[A-Za-z0-9_]") {
    set $block_deserialization 1;
}

if ($query_string ~* "serialize\(") {
    set $block_deserialization 1;
}

if ($block_deserialization = 1) {
    return 403;
}

# Enable logging for blocked requests (for analysis)
if ($block_sql_injections = 1) {
    access_log /var/log/nginx/blocked_requests.log;
}

if ($block_xss = 1) {
    access_log /var/log/nginx/blocked_requests.log;
}

if ($block_rce = 1) {
    access_log /var/log/nginx/blocked_requests.log;
}

if ($block_xxe = 1) {
    access_log /var/log/nginx/blocked_requests.log;
}

if ($block_deserialization = 1) {
    access_log /var/log/nginx/blocked_requests.log;
}

# Note:
## Block Components with Known Vulnerabilities
# Use a web application firewall (WAF) for more comprehensive protection.
# Update components regularly and scan for vulnerabilities.

```
