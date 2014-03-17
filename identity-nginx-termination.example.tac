from Crypto.PublicKey import RSA

from identity.persona import BrowseridResource
from identity.basic import WhoamiResource, PeerVerifier

from twisted.application.internet import TCPServer
from twisted.application.service import Application
from twisted.python.filepath import FilePath
from twisted.web.resource import Resource
from twisted.web.server import Site


fileRoot = FilePath(__file__).parent()

with fileRoot.child('private-key.pem').open() as infile:
    rsaKey = RSA.importKey(infile)

verifier = PeerVerifier(acceptCertAsHeader=True)

root = Resource()
wellKnown = Resource()
root.putChild('.well-known', wellKnown)
wellKnown.putChild('browserid', BrowseridResource(rsaKey, verifier))
root.putChild('whoami', WhoamiResource(verifier))

site = Site(root)

application = Application('identity')
TCPServer(8880, site, interface='127.0.0.1').setServiceParent(application)
