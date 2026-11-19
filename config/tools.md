# Security tools

## Burp Suite Community
Download:
https://portswigger.net/burp/communitydownload

Use:
Proxy > HTTP history

Inspect normal authenticated browsing activity.
Do not replay or modify production requests without
a defined test plan and authorization.

## OWASP ZAP
Download:
https://www.zaproxy.org/download/

Start with passive scanning.
Restrict the context to authorized application URLs.
Do not run active attacks against production.

## SQL injection
Use DVWA or OWASP Juice Shop in an isolated local lab.
Test staging copies before testing production.
Use parameterized queries for remediation.

## Postman
https://www.postman.com/downloads/
Use for documented, authorized API testing.
Never export live authentication secrets.
