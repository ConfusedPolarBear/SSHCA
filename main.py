#!/usr/bin/python3

# Copyright 2020 Matt Montgomery
# License: AGPLv3

import os
import tempfile
import sshkeygen

SSHTEMP_PREFIX='sshauth'

def loggedIn():
	keys = []

	# ssh writes files to /tmp/sshauth.XXXXXXXXXXXXXXX containing authentication information
	for fn in os.listdir('/tmp'):
		if not fn.startswith(SSHTEMP_PREFIX):
			continue

		# keys are written to lines similar to 'publickey ssh-TYPE PUBLIC_KEY_CONTENTS_GO_HERE'
		with open('/tmp/' + fn, 'r') as f:
			auth = f.read()

			start = auth.find('publickey ') + len('publickey ')
			end   = auth.find('\n', start)
			key   = auth[start:end]

			keys.append(key)

	return keys

agent = sshkeygen.testAgent()
out = agent['stdout']
err = agent['stderr']

# Check if the agent is running
if err.find('Error connecting') != -1:
	print(f'ssh-add output: {err}')
	print('Cannot connect to ssh-agent, start it with \'eval `ssh-agent`\'')
	exit(1)

# Check for identities
elif len(out) <= 20:
	print(f'ssh-add output: {out}')
	print('ssh-agent does not appear to have any identities')
	exit(1)

pubkey = loggedIn()[0]
print(f'signing key {pubkey}')

cert = sshkeygen.sign('debian', '30m', [ 'main', 'asdf' ], pubkey)
print(f'cert is {cert}')

print(loggedIn())
