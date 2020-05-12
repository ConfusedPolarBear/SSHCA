# Copyright 2020 Matt Montgomery
# License: AGPLv3

# TODO: parse ssh-keygen -Lf - output and output JSON to be audit logged
# TODO: Audit log JSON should also contain raw ssh-keygen output as base64

import os, pwd
import re
import secrets
import subprocess
import sys
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

def sign(template, username, publicKey):
    return signRaw(username, template.allowed, template.notAfter, template.principals, template.extensions, publicKey)

def signRaw(user, allowed, notAfter, principalsList, extensionsList, pubkey):
    if (user not in allowed) and ('*' not in allowed):
        raise Exception(f'User {user} is not allowed to use this template')

    # generates a key identity of the form username.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa for auditing purposes
    identity = user + '.' + secrets.token_hex(16)

    # convert 30m to +30m
    notAfter = '+' + sanitize(notAfter)

    # convert [ 'principal1', 'principal2' ] to principal1,principal2
    principals = ''
    for i in principalsList:
        clean = sanitize(i)
        principals += clean + ','
    principals = principals[:-1]        # trim trailing comma

    args = ['ssh-keygen', '-U', '-s', 'ca.pub', '-I', identity, '-V', notAfter, '-n', principals]

    # convert [ 'extension', 'extension2' ] to -O extension -O extension2
    for i in extensionsList:
        # don't need to sanitize this because it's coming from a trusted template
        args.append('-O')
        args.append(i)

    pubkey += '\n'
    signed = ''
    with tempfile.NamedTemporaryFile() as temp:
        temp.file.write(pubkey.encode('utf-8'))
        temp.file.seek(0)

        signed = temp.name + '-cert.pub'

        args.append(temp.name)
        out = run(args)

        if out['process'].returncode != 0:
            error = out['stderr']
            print(f'Unable to sign certificate: {error}')

    with open(signed, 'r') as f:
        contents = f.read()
        os.remove(signed)
        return cleanCert(contents)

def cleanCert(raw):
    # remove the filename
    parts = raw.split(' ')
    return parts[0] + ' ' + parts[1]

def testAgent():
    return run(['ssh-add', '-l'])

def getUsername():
    return pwd.getpwuid(os.getuid()).pw_name
