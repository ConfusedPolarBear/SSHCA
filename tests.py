import unittest

import dateutil.parser
import datetime

import sshkeygen

class TestCertificates(unittest.TestCase):
    inst = 0

    def test_parsing(self):
        # ewww
        global inst
        inst = self

        rawFirst = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIF0a+a87J8fsklKv4vhvh286tZL/HxFEdM2ZpbBJoPDXAAAAINZ6phAM228hSdlhJSkwpmgj+t5AKkikQHIqtpNwjkOkAAAAAAAAAAAAAAABAAAALWlkZW50aXR5LjRhNWI1YTIyLWE4MDgtNDI3Mi1hNGRjLTE5Y2E5ZGUzM2FkYwAAABwAAAAKcHJpbmNpcGFsMQAAAApwcmluY2lwYWwyAAAAAF5llcQAAAAAXmbnpAAAADEAAAAQdGVzdEBleGFtcGxlLmNvbQAAAAAAAAARdGVzdDJAZXhhbXBsZS5jb20AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBOOOdn0HxakuXkbdNIUs77OKRbXs8GVc1rpwmyjib73QAAAFMAAAALc3NoLWVkMjU1MTkAAABAgKjoWGMawtZYyZLm0CWj/R2n2CRK+L9caIetTqLD37L62xT9SIoytbwtn68bAAZiAfEGPY3v1lAeo5jDnuS2Cw== comment"
        rawSecond = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAINz/bPTATvhXTM416sZuDPv4BesXaS5AohK+CZCXjAf6AAAAINZ6phAM228hSdlhJSkwpmgj+t5AKkikQHIqtpNwjkOkAAAAAAAAAAAAAAABAAAALWlkZW50aXR5LjRhNWI1YTIyLWE4MDgtNDI3Mi1hNGRjLTE5Y2E5ZGUzM2FkYwAAAAAAAAAAXmWTqAAAAABebs6GAAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgTjjnZ9B8WpLl5G3TSFLO+zikW17PBlXNa6cJso4m+90AAABTAAAAC3NzaC1lZDI1NTE5AAAAQFGRP2sjdyQBRyK6yOJpVKxjQMjRPoAiuzlTgzd3Zl37xC0NXMwUEbJfbSk6NKWK+LGBb5ETBhBTArJ2sYeqxQc= comment"
        rawThird = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgtgU3wF7WZGELxksYJCgUiNWuZX3TSb1kEGJjzQIWb1kAAAADAQABAAABAQDNU3bf+l6MYPtfC1gS7Tq8Iykw0t9aN0WJuUoX225vvu0SBxiNpLfr+I0kOpr6DdzOUG4Z4W+ETaihzNKMvKXIH0xfIpgslNRXzijNelpov+Qg+ANu2/Vdm2u5/QQc21OXkGWGRxRIXaNoMCaZEX/YsCkJehdXpzAVnN8m3OjOXbI3Tv2V5+CQds5Od0B7R0KMyw4YhaouHNRqLmAp3kNJDu7I+4+ysCwGhpKFKzqZkejC7zyqlc2RQtrLRj54p8iQ8A7Xdm9+mduk7abQUSz5XOgXqvtDX7kdo9K1AfBCiQD95ByvH1JkjoDdCh5Wg5474OLZD/SJR/SzE95LRKGlAARjCvX8AU4AAAABAAAACGlkZW50aXR5AAAAHAAAAApwcmluY2lwYWwxAAAACnByaW5jaXBhbDIAAAAAXmWY0AAAAABjiqOvAAAAAAAAAGQAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgTjjnZ9B8WpLl5G3TSFLO+zikW17PBlXNa6cJso4m+90AAABTAAAAC3NzaC1lZDI1NTE5AAAAQHWql+9ykyWXlpNUleaRiuxcwDZwz8WlChSob6hDFYrfoWnr7/q4MxuP5pBwz90lSruHtNFVDjEgMzKQ+cYpogY= long comment with spaces"
        rawFourth = "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgQ5adGcVRXAfYDcIaJU0p2YSDvgKXAsl28QMlM2lo/AoAAAADAQABAAACAQC6x5HdNwWI+Djre3bsVJjtORGaolqa54MeFEliVirW+vE8ZFQFKcrUjv51a5V098JfTAb5qBDodJ5+0x0YTzNAiZESMkp2IWlBRoQ/esYFW9mw/89b+FvNxuxpf6JbbiGYBpFDJF8gKFPac1IfX0+8qtlW/7oeoic73pgErDcMNm+g1NRMHx5foBQn+/1x0RqhkB7ciKXLuHpaiKLigc9wr5684jonP6nIrl3OyZTBcq1K67L0WvTFOevVOer+DOM456mRs37r01f9KZK+gewlniw0B5CQEz/oqlrG0BRnXSl8AExSUO4oOljDudP5IW1aHYIht40b4vjW10hZ8cTeApAIOpNhqpB0XZllsc4NZ9PhXkOQAoF0MS+vedaxhoLYnOJMF8jIG4epUgzx/Jq+XA9TS6jkP7eK6Y0DbcKYOkT7kl7pqKOx3zbXnNRXBJPnWn1FYzny8qxQj+q/5Q7TnVacRuXHh18axmSk/rvfi90ytoH1J66pAjKnw7C+rXtCdPiIGIQ7Ciq69P1w+Gc709YydLv151zEPeJ/a2xW094ga9IooaZKlvRfMWAiWF2rwtWH2yDw+KnDL4JYHDpcM+91qt7bPAvK9ekB1sKqo5MFmXLu4nb+Kqmqf1lftR9bcR47kTmc6vfyumPOBDnTW8flBOmMmwkQT4w89ZzZLwAAAAAAAAAAAAAAAQAAACxhZG1pbjQ2LmMxNmNkNWJkLTdlZWEtNDdkMy04ZTNkLTdjYWRlYTg4ZTdkNQAAACQAAAAEdGVzdAAAAAlqb2huc21pdGgAAAALVVNFUjpkZWJpYW4AAAAAXnwH8AAAAABehUKyAAAAAAAAABIAAAAKcGVybWl0LXB0eQAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACB/IVSh7FfyqUSVKvCdWZpiSP91FsjpEDqf6PGrilzyAgAAAFMAAAALc3NoLWVkMjU1MTkAAABAmJe6QIagMo3YBSiX1/oiqfDiW3Ihh007tUjKX+h/PULTvueLo+9ydhfMT5dflZ3WzQLRpSdjWTqKBcUiX45JCA=="

        first = sshkeygen.parseCertificate(rawFirst)
        second = sshkeygen.parseCertificate(rawSecond)
        third = sshkeygen.parseCertificate(rawThird)
        fourth = sshkeygen.parseCertificate(rawFourth)
        
        compare(
            first,
            'ssh-ed25519-cert-v01@openssh.com',
            'user',
            'ED25519-CERT SHA256:w11qyQ9J5Z1J7TpMQu1KYx/fjZx+G/zxc4CJWavzBqE',
            'ED25519 SHA256:AUOJCk2cF0QhO6+5CTSZqdpqdF/J/tlyeqTzyBuCB9c',
            'identity.4a5b5a22-a808-4272-a4dc-19ca9de33adc',
            0,
            datetime.datetime(2020, 3, 8, 20, 3, 0),
            datetime.datetime(2020, 3, 9, 20, 4, 36),
            [ 'principal1', 'principal2' ],
            [ 'test@example.com UNKNOWN OPTION (len 0)', 'test2@example.com UNKNOWN OPTION (len 0)' ],
            [ 'permit-X11-forwarding', 'permit-agent-forwarding', 'permit-port-forwarding', 'permit-pty', 'permit-user-rc' ])
        
        compare(
            second,
            'ssh-ed25519-cert-v01@openssh.com',
            'user',
            'ED25519-CERT SHA256:w11qyQ9J5Z1J7TpMQu1KYx/fjZx+G/zxc4CJWavzBqE',
            'ED25519 SHA256:AUOJCk2cF0QhO6+5CTSZqdpqdF/J/tlyeqTzyBuCB9c',
            'identity.4a5b5a22-a808-4272-a4dc-19ca9de33adc',
            0,
            datetime.datetime(2020, 3, 8, 19, 54, 0),
            datetime.datetime(2020, 3, 15, 19, 55, 34),
            [ ],
            [ ],
            [ 'permit-X11-forwarding', 'permit-agent-forwarding', 'permit-port-forwarding', 'permit-pty', 'permit-user-rc' ])
        
        compare(
            third,
            'ssh-rsa-cert-v01@openssh.com',
            'user',
            'RSA-CERT SHA256:UORuiL6Z6WpwCfbF7jh/D+N8koXU/BvPMR8AXN6r3aY',
            'ED25519 SHA256:AUOJCk2cF0QhO6+5CTSZqdpqdF/J/tlyeqTzyBuCB9c',
            'identity',
            1234798634598734,
            datetime.datetime(2020, 3, 8, 20, 16, 0),
            datetime.datetime(2022, 12, 2, 19, 17, 35),
            [ 'principal1', 'principal2' ],
            [ ],
            [ 'permit-X11-forwarding', 'permit-agent-forwarding', 'permit-pty', 'permit-user-rc' ])
        
        compare(
            fourth,
            'ssh-rsa-cert-v01@openssh.com',
            'user',
            'RSA-CERT SHA256:SpOooYzN0e29y9ik4gdWwNAnHUPZlUnUHWcXOE3Cmcc',
            'ED25519 SHA256:Lp9feuuEwvu39rO14hXxsowpNck7hVx9hFAv+Drh9No',
            'admin46.c16cd5bd-7eea-47d3-8e3d-7cadea88e7d5',
            0,
            datetime.datetime(2020, 3, 25, 20, 40, 0),
            datetime.datetime(2020, 4, 1, 20, 41, 6),
            [ 'test', 'johnsmith', 'USER:debian' ],
            [ ],
            [ 'permit-pty' ])

def compare(cert, algorithm, type, publicKey, signingKey, identity, serial, notBefore, notAfter, principals, critical, extensions):
    inst.assertEqual(cert.algorithm, algorithm)
    inst.assertEqual(cert.type, type)
    inst.assertEqual(cert.publicKey, publicKey)
    inst.assertEqual(cert.signingKey, signingKey)
    inst.assertEqual(cert.identity, identity)
    inst.assertEqual(cert.serial, serial)
    inst.assertEqual(cert.notBefore, str(notBefore))
    inst.assertEqual(cert.notAfter, str(notAfter))
    inst.assertEqual(cert.principals, principals)
    inst.assertEqual(cert.criticalOptions, critical)
    inst.assertEqual(cert.extensions, extensions)

if __name__ == '__main__':
    unittest.main()
