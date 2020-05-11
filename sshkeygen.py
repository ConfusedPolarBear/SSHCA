# Copyright 2020 Matt Montgomery
# License: AGPLv3

import os
import re
import secrets
import subprocess
import tempfile

def sanitize(raw):
	return re.sub('[^A-Za-z0-9]', '', raw)

def run(args):
	print(f'\nRUNNING NEW PROGRAM {args}')
	process = subprocess.run(args, capture_output = True)
	out = process.stdout.decode('utf-8')
	err = process.stderr.decode('utf-8')

	print(f'    stdout: {out}')
	print(f'    stderr: {err}')

	return {
		'process': process,
		'stdout': out,
		'stderr': err
	}

def sign(user, notAfter, principalsList, pubkey):
	# ssh-keygen -s ca -I user.AUDIT -V +2m -n principal public-key.pub

	user = sanitize(user)
	# generates a key identity of the form username.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	identity = user + '.' + secrets.token_hex(16)

	# convert 30m to +30m
	notAfter = '+' + sanitize(notAfter)

	# convert [ 'principal1', 'principal2' ] to principal1,principal2
	principals = ''
	for i in principalsList:
		clean = sanitize(i)
		principals += clean + ','
	principals = principals[:-1]		# trim trailing comma

	pubkey += '\n'
	signed = ''
	with tempfile.NamedTemporaryFile() as temp:
		temp.file.write(pubkey.encode('utf-8'))
		temp.file.seek(0)

		signed = temp.name + '-cert.pub'
		out = run(['ssh-keygen', '-U', '-s', 'ca.pub', '-I', identity, '-V', notAfter, '-n', principals, '-C', '', temp.name])

		if out['process'].returncode != 0:
			error = out['stderr'].decode('utf-8')
			print(f'Unable to sign certificate: {error}')

	with open(signed, 'r') as f:
		contents = f.read()
		os.remove(signed)
		return contents

def testAgent():
	return run(['ssh-add', '-l'])
