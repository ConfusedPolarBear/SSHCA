# SSH CA

## Short Description

SSH CA is a secure, centralized location for storing and generating OpenSSH certificates.

## Features

* Provide quick access to Linux servers over SSH by issuing certificates
* Audit all certificate requests
* Revoke a certificate across all connected servers with a single API call

## License

This project is licensed under the terms of the AGPLv3 license.

## How do I install this?

* On all servers you want to trust the new certificate authority, modify ``/etc/ssh/sshd_config`` to contain the following:
```
LogLevel INFO
TrustedUserCAKeys /etc/ssh/ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
RevokedKeys /etc/ssh/revoked.krl
```

* Changing the log level to info causes OpenSSH to log details about the certificate used to authenticate
* Create a new file called ``/etc/ssh/ca.pub`` which contains the certificate authority's public key
* Modify your crontab so it updates the list of revoked keys
