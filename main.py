#!/usr/bin/python3

# Copyright 2020 Matt Montgomery
# License: AGPLv3

import os, pwd, sys, shutil
import tempfile
import jsonpickle
import syslog
from configparser import ConfigParser

import sshkeygen
from templates import Template

SSHTEMP_PREFIX='sshauth'

rawConfig = ConfigParser()
config = ConfigParser()

templates = []
isDebug = False

def abort(msg):
    print(f'FATAL: {msg}')
    exit(1)

def debug(msg):
    if isDebug:
        print(msg)

# reinventing the wheel a bit but only because python's bool() function is *advanced* stupid
def toBool(string):
    return string.lower() in ('True', 'true')

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

            fingerprint = sshkeygen.fingerprint(key)

            keys.append(f'{key} {fingerprint}')

    return keys

def checkAgent():
    agent = sshkeygen.testAgent()
    out = agent['stdout']
    err = agent['stderr']

    # Check if the agent is running
    if err.find('Error connecting') != -1:
        debug(f'ssh-add output: {err}')
        abort('Cannot connect to ssh-agent, start it with \'eval `ssh-agent`\'')

    # Check for identities
    elif len(out) <= 20:
        debug(f'ssh-add output: {out}')
        abort('ssh-agent does not appear to have any identities')

def getFromList(items, initialPrompt, default):
    length = len(items)

    if length == 1:
        print(f'Autoselecting {items[0]}')
        return items[0]

    print()
    print(initialPrompt)

    for i in range(length):
        print(f'{i}: {items[i]}')

    while True:
        raw = input(f'Enter selection ({default}): ')
        try:
            if raw == '':
                raw = default

            number = int(raw)
            if number < 0:
                raise Exception('less than zero')
            return items[number]
        except:
            print('Invalid selection, try again')
            print()

def getPublicKey():
    # strip off the fingerprint
    raw = getFromList(loggedIn(), 'A key could not be automatically selected for signing. Available options:', 0).split(' ')
    return raw[0] + ' ' + raw[1]

def loadTemplates():
    with open('config/templates.json', 'a+') as f:
        f.seek(0)
        raw = f.read()
        if raw == '':
            sample = [ Template('example', [ 'username1', 'username2' ], '24h', [ 'principal1', 'principal2' ]) ]
            raw = jsonpickle.encode(sample)

            open('config/templates.json', 'w').write(raw)

            abort('No templates have been defined, a sample file was created')

        return jsonpickle.decode(raw)

def load():
    try:
        templates.clear()
        for i in loadTemplates():
            templates.append(i)
    except Exception as e:
        abort(f'Failed to read templates file. Error: {e}')

    rawConfig.read('config/config.ini')
    
    if not rawConfig.has_section('main'):
        rawConfig.add_section('main')

    # what is scoping in python
    global config
    global isDebug

    config = rawConfig['main']
    print('is debug' + config.get('debug'))
    isDebug = toBool(config.get('debug', fallback='False'))
    print('is debug' + str(isDebug))
    sshkeygen.setDebug(isDebug)

    rawConfig.set(config.name, 'debug', str(isDebug))
    save()

def save():
    with open('config/config.ini', 'w') as f:
        rawConfig.write(f)

def getSerial():
    serial = int(config.get('serial', fallback='0'))
    serial = serial + 1

    rawConfig.set(config.name, 'serial', str(serial))

    save()

    return serial

def main():
    load()

    checkAgent()
    pubkey = getPublicKey()

    debug(f'signing key {pubkey}')

    chosen = getFromList(templates, 'Pick certificate template to use', 0)

    username = sshkeygen.getUsername()
    cert = sshkeygen.sign(chosen, username, pubkey, getSerial())

    rawAudit = sshkeygen.parseCertificate(cert)
    rawAudit.client = os.getenv('SSH_CONNECTION')    # get SSH client information

    audit = rawAudit.toJSON()
    syslog.openlog('sshca')
    syslog.syslog(audit)

    width = shutil.get_terminal_size().columns

    print()
    print('+-' * int(width / 2))
    print(cert)
    print('+-' * int(width / 2))

if __name__ == '__main__':
    main()
