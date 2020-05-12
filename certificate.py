import datetime as dt
import base64

class Certificate():
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
    raw = ''

    def __init__(self, algorithm, type, publicKey, signer, identity, serial, notBefore, notAfter, principals, critical, extensions, raw):
        self.algorithm = algorithm
        self.type = type
        self.publicKey = publicKey
        self.signingKey = signer
        self.identity = identity
        self.serial = serial
        self.notBefore = str(notBefore)
        self.notAfter = str(notAfter)
        self.principals = principals
        self.criticalOptions = critical
        self.extensions = extensions

        self.raw = base64.b64encode(raw.encode('utf-8'))
        self.raw = self.raw.decode('utf-8')

    def __str__(self):
        return str(self.__dict__)
