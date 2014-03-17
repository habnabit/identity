from Crypto.PublicKey import RSA

from identity.persona import BrowseridResource
from identity.basic import PeerVerifier, WhoamiResource

from twisted.application.internet import SSLServer
from twisted.application.service import Application
from twisted.internet import ssl
from twisted.python.filepath import FilePath
from twisted.web.resource import Resource
from twisted.web.server import Site

import sys


if sys.platform == 'darwin':
    import ctypes
    ctypes.CDLL('libssl.dylib').X509_TEA_set_state(0)

fileRoot = FilePath(__file__).parent()
sslRoot = fileRoot.child('ssl')

with fileRoot.child('private-key.pem').open() as infile:
    rsaKey = RSA.importKey(infile)
with sslRoot.child('server.pem').open() as infile:
    serverCert = ssl.PrivateCertificate.loadPEM(infile.read())

authorityCerts = []
for ca in ['ca.pem', 'sub.class1.server.ca.pem', 'sub.class1.client.ca.pem']:
    with sslRoot.child(ca).open() as infile:
        authorityCerts.append(ssl.Certificate.loadPEM(infile.read()))

sslContextFactory = serverCert.options(*authorityCerts)
sslContextFactory.requireCertificate = False

verifier = PeerVerifier()

root = Resource()
wellKnown = Resource()
root.putChild('.well-known', wellKnown)
wellKnown.putChild('browserid', BrowseridResource(rsaKey, verifier))
root.putChild('whoami', WhoamiResource(verifier))

site = Site(root)

application = Application('identity')
SSLServer(5443, site, sslContextFactory, interface='::').setServiceParent(application)
