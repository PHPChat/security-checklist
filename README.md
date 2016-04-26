Security Checklist
===================

- [ ] Is the website only served over https? 

*Test:*

```bash
$ curl -s -I http://example.org | grep '^HTTP'
HTTP/1.1 301 Moved Permanently
```

```bash
$ curl -s -I https://example.org | grep '^HTTP'
HTTP/1.1 200 OK
```

- [ ] Is the HSTS http-header set? 

*Test:*

```bash
$ curl -s -I https://example.org | grep '^Strict'
Strict-Transport-Security: max-age=63072000; includeSubdomains;
```

- [ ] Is the server certificate at least 4096 bits?

*Test:*

```bash
$ openssl s_client -showcerts -connect example.org:443 |& grep '^Server public key'
Server public key is 4096 bit
```

- [ ] Is TLS1.2 the only supported protocol? 

*Test:*

```bash
$ curl --sslv3 https://example.org
curl: (35) Server aborted the SSL handshake
```

```bash
$ curl --tlsv1.0 -I https://example.org
curl: (35) Server aborted the SSL handshake
```

```bash
$ curl --tlsv1.1 -I https://example.org
curl: (35) Server aborted the SSL handshake
```

```bash
$ curl --tlsv1.2 -s -I https://example.org | grep 'HTTP'
HTTP/1.1 200 OK
```

- [ ] Do all supported symmetric ciphers use at least 256 bit keys?

*Test:*

```bash
$ nmap --script ssl-enum-ciphers -p 443 example.org
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA - strong
|       TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 - strong
|       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 - strong
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA - strong
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 - strong
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - strong
|     compressors:
|       NULL
|_  least strength: strong
```

- [ ] Is the Diffie-Hellman prime at least 4096 bits? 

*Test:*

```bash
$ openssl s_client -connect example.com:443 -cipher "EDH" |& grep "^Server Temp Key"
Server Temp Key: DH, 4096 bits
```

- [ ] Have you ensured that your content cannot be embedded in a frame on another website?

*Test:*

```bash
$ curl -s -I https://example.org | grep '^X-Frame-Options'
X-Frame-Options: SAMEORIGIN

$ curl -s -I https://example_2.org | grep '^X-Frame-Options' 
X-Frame-Options: DENY # Also acceptable
```

- [ ] Have you ensured that the Internet Explorer content sniffer is disabled?

*Test:*

```bash
$ curl -s -I https://example.org | grep '^X-Content'
X-Content-Type-Options: nosniff
```

- [ ] Do all assets delivered via a content delivery network include subresource integrity hashes?

*Example:*

```bash
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.2/css/bootstrap.min.css" integrity="sha384-y3tfxAZXuh4HwSYylfB+J125MxIs6mR5FOHamPBG064zB+AFeWH94NdvaCBm8qnd" crossorigin="anonymous">
```

- [ ] Are password entropy checks done during user sign-up, using, say [AUTH_PASSWORD_VALIDATORS](https://docs.djangoproject.com/en/1.9/topics/auth/passwords/#enabling-password-validation)?

- [ ] Are you storing only the hash of your users password, and not the cleartext password, using (say) [PBKDF](https://en.wikipedia.org/wiki/PBKDF2)?

- [ ] Are failed login attempts throttled and IP addresses banned after a number of unsuccessful attempts, using (say) [django-axes](https://pypi.python.org/pypi/django-axes)?

- [ ] Are you using [fail2ban](http://www.fail2ban.org/wiki/index.php/Main_Page) to throttle ssh login attempts?

*Test:*

```bash
sudo fail2ban-client status sshd
```

- [ ] Have you disabled password-based login over ssh, and only allowed key-based login?

*Test:*

```bash
$ cat /etc/ssh/sshd_config  | grep '^Password'
PasswordAuthentication no
```

- [ ] Do session cookies have the 'Secure' and 'HttpOnly' flag set?

*Test:*

```bash
$ curl -s -I example.com/url_that_sets_cookie | grep '^Set-Cookie'
Set-Cookie: ****;Path=/;Expires=Fri, 16-Mar-2018 19:18:51 GMT;Secure;HttpOnly;Priority=HIGH
```

- [ ] Do forms set a cross-site request forgery cookie?

*Test:*

```bash
$ curl -s -I https://example.com/url_with_form | grep '^Set-Cookie'
Set-Cookie: csrftoken=*****************; expires=Thu, 16-Mar-2017 01:26:03 GMT;Secure;HttpOnly; Max-Age=31449600; Path=/
```

- [ ] Are all user uploads validated for expected content type? 

- [ ] Are the permissions of all uploaded files readonly?

- [ ] Are all form fields (with the exception of password fields) validated with a restrictive regex?

- [ ] Are there unit tests (say, using [Selenium](http://www.seleniumhq.org/)) which show that one authenticated user cannot access another user's content?

- [ ] Have you made sure that database passwords, server signing keys, and hash salts are not checked into source control?

- [ ] Do you have an account recovery flow? Delete it immediately. 


> This list was originally published on [securitychecklist.org](https://securitychecklist.org/) and maintained by [PHPChat](https://phpchat.co) Community.