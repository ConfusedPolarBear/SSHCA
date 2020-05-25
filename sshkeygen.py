# Copyright 2020 Matt Montgomery
# License: AGPLv3

# TODO: add filename sanitization to parseCertificateByName

import os, pwd
import re
import secrets
import subprocess
import sys
import tempfile
import datetime as dt
import dateutil.parser as dtp
from certificate import Certificate

isDebug = False

def setDebug(_debug):
    global isDebug
    isDebug = _debug
    debug('Debug mode enabled')

def debug(msg):
    if isDebug:
        print(msg)

def sanitize(raw):
    return re.sub('[^A-Za-z0-9]', '', raw)

def run(args, switchUser = False):
    if switchUser:
        socket = ''
        with open('/tmp/sshca-socket', 'r') as f:
            socket = f.read()

        socket = socket.replace('\n', '')

        os.putenv('SSH_AUTH_SOCK', socket)
        debug('switching user')
        sudo = ['sudo', '-u', 'sshca', '--preserve-env=SSH_AUTH_SOCK']
        sudo.reverse()

        for i in sudo:
            args.insert(0, i)

    debug(f'\nRUNNING NEW PROGRAM {args}')
    process = subprocess.run(args, capture_output = True)
    out = process.stdout.decode('utf-8')
    err = process.stderr.decode('utf-8')

    debug(f'    stdout:\n{out}')
    debug(f'    stderr:\n{err}')

    return {
        'process': process,
        'stdout': out,
        'stderr': err
    }

def sign(template, username, publicKey, serial):
    return signRaw(username, template.allowed, template.notAfter, template.principals, template.extensions, publicKey, serial)

def signRaw(user, allowed, notAfter, principalsList, extensionsList, pubkey, serial):
    if (user not in allowed) and ('*' not in allowed):
        raise Exception(f'User {user} is not allowed to use this template')

    # generates a key identity of the form username.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa for auditing purposes
    identity = user + '.' + secrets.token_hex(16)

    # convert 30m to +30m
    notAfter = '+' + sanitize(notAfter)

    # convert [ 'principal1', 'principal2' ] to principal1,principal2
    principals = ''
    for i in principalsList:
        clean = i.replace('%u', user)
        principals += clean + ','
    principals = principals[:-1]        # trim trailing comma

    args = ['ssh-keygen', '-U', '-s', 'config/ca.pub', '-I', identity, '-V', notAfter, '-n', principals, '-z', str(serial)]

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

        run(['chmod', 'a+r', temp.name])
        run(['file', temp.name])
        run(['file', temp.name], True)

        args.append(temp.name)
        out = run(args, True)

        if out['process'].returncode != 0:
            error = out['stderr']
            print(f'Unable to sign certificate: {error}')

    with open(signed, 'r') as f:
        contents = f.read()
        run(['rm', signed], True)
        return cleanCert(contents)

def cleanCert(raw):
    # remove the filename
    parts = raw.split(' ')
    return parts[0] + ' ' + parts[1]

def fingerprint(contents):
    with tempfile.NamedTemporaryFile() as temp:
        temp.file.write(contents.encode('utf-8'))
        temp.file.seek(0)

        # returns "256 SHA256:DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFABC no comment (ED25519)"
        fpr = run(['ssh-keygen', '-l', '-f', temp.name])['stdout']
        return fpr.split(' ')[1]

def testAgent():
    return run(['ssh-add', '-l'], True)

def getUsername():
    return pwd.getpwuid(os.getuid()).pw_name

def parseCertificate(contents):
    with tempfile.NamedTemporaryFile() as temp:
        temp.file.write(contents.encode('utf-8'))
        temp.file.seek(0)

        return parseCertificateByName(temp.name)

def parseCertificateByName(filename):
    out = run(['ssh-keygen', '-L', '-f', filename])
    output = out['stdout']
    raw = output.split('\n')

    # Sample output:
    # (stdin):1:
    #         Type: ssh-ed25519-cert-v01@openssh.com user certificate
    #         Public key: ED25519-CERT SHA256:/4nH2Vyt+Hbagn5Dh2QkuVW/7CqpU9PK+SjyFzKhFeE
    #         Signing CA: ED25519 SHA256:C/Hd+04AdgiNmpG/MM6+Q/JCCBdQxx2rK3SSFaE8Br8
    #         Key ID: "user.89fccec2-08b7-4748-8631-70d21b8a5f38"
    #         Serial: 0
    #         Valid: from 2020-03-21T22:14:00 to 2020-03-28T22:15:29
    #         Principals:
    #                 test
    #                 johnsmith
    #         Critical Options: (none)
    #         Extensions:
    #                 permit-pty

    algorithm = ''
    type = ''
    publicKey = ''
    signingKey = ''
    identity = ''
    serial = 0
    notBefore = dt.datetime(1, 1, 1)
    notAfter = dt.datetime(1, 1, 1)
    principals = []
    criticalOptions = []
    extensions = []
    list = ''

    # Skip the first line since it's the filename
    for i in range(1, len(raw)):
        # Deindent by one level
        line = raw[i][8:]
        # print(f'processing line \"{line}\"')

        if line.startswith(' ' * 8):
            # print(f'found indented line for {list}')
            item = line.strip()
            if item == '':
                continue

            elif list == 'principals':
                principals.append(item)

            elif list == 'critical options':
                criticalOptions.append(item)

            elif list == 'extensions':
                extensions.append(item)

            else:
                print(f'Unknown list {list} for item {item}')

        elif line.startswith('Type'):
            split = getValue(line).split(' ')
            
            algorithm = split[0]
            type = split[1]

        elif line.startswith('Public key'):
            publicKey = getValue(line)

        elif line.startswith('Signing CA'):
            signingKey = getValue(line)

        elif line.startswith('Key ID'):
            identity = getValue(line)[1:-1]

        elif line.startswith('Serial'):
            serial = int(getValue(line))

        elif line.startswith('Valid'):
            valid = getValue(line).split(' ')
            notBefore = dtp.parse(valid[1])
            notAfter = dtp.parse(valid[3])

        elif line.startswith('Principals') or line.startswith('Critical Options') or line.startswith('Extensions'):
            list = line.split(':')[0].lower()

    parsed = Certificate(algorithm, type, publicKey, signingKey, identity, serial, notBefore, notAfter, principals, criticalOptions, extensions, output)

    return parsed

def getValue(raw):
    start = raw.find(':') + 2
    return raw[start:]

if __name__ == '__main__':
    cert = sys.argv[1]
    # print(f'parsing certificate {cert}')

    ret = parseCertificate(cert)
    print(ret.toJSON())
