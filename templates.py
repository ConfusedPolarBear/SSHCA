# TODO: add doc strings

class Template():
    name = ''
    allowed = []
    notAfter = ''
    principals = []
    extensions = []

    def __init__(self, _name, _allowed, _notAfter, _principals, _extensions = []):
        self.name = _name
        self.allowed = _allowed
        self.notAfter = _notAfter
        self.principals = _principals
        self.extensions = _extensions
