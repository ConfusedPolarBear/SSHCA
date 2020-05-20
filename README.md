# SSH CA

## Warning
This project is under active development and should **not be used in production**!

## Short Description

SSH CA is a secure, centralized location for storing and generating OpenSSH certificates. User and host certificates are supported.

## Features

* Provide quick access to Linux servers over SSH by issuing certificates
* Audit all certificate requests
* Revoke a certificate across all connected servers with a single API call

## License

This project is licensed under the terms of the AGPLv3 license.

## How do I install this?

* Setup a new certificate authority by running ``./setup-ca.sh KEY_DIRECTORY``. This will generate two new SSH keys - one to sign host certificates and another to sign user certificates.
  * ``KEY_DIRECTORY`` is the path to the directory in which to store the private keys for the newly created authority
  * The script will prompt you for passwords to encrypt the private keys - **do not forget these as there is no way to recover them!**
  * The public keys for the newly created authority will be stored in the current directory - you should save these somewhere as they will be needed in the next steps
* Load the private keys into ``ssh-agent`` by running ``ssh-add KEY_DIRECTORY/{ca,host}`` and entering the passwords to decrypt the keys if prompted
* On all servers that need to trust the new certificate authority, run ``./setup-host.sh USER_CA_PUBLIC_KEY``. This will:
  * Backup the original ``sshd_config`` file
  * Use a host certificate from ``/etc/ssh/host-cert.pub``
  * Only allow logins to users with a listed principal in ``/etc/ssh/principals/USERNAME``
