from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

from twisted.python.filepath import FilePath
from twisted.web.resource import Resource
from twisted.web.template import tags, renderElement

from identity.basic import furnishRequestEmail, UnverifiedPeer

import base64
import json
import posixpath


with FilePath(__file__).sibling('js').child('authentication.js').open() as infile:
    AUTHENTICATION_JS = infile.read()


def b64uencode(s):
    return base64.urlsafe_b64encode(str(s)).replace('=', '')

def sign(payload, key):
    encoded_header = b64uencode(json.dumps({'alg': 'RS256'}))
    signing_input = encoded_header + '.' + b64uencode(json.dumps(payload))
    signature = PKCS1_v1_5.new(key).sign(SHA256.new(signing_input))
    return signing_input + '.' + b64uencode(signature)


class BrowseridResource(Resource):
    def __init__(self, rsaKey):
        Resource.__init__(self)
        self.rsaKey = rsaKey
        self.putChild('authentication', BrowseridAuthenticationResource())
        self.putChild('provisioning', BrowseridProvisioningResource(self.rsaKey))

    def render_GET(self, request):
        request.setHeader('content-type', 'application/json')
        ret = {
            'public-key': {
                'algorithm': 'RS',
                'n': str(self.rsaKey.n),
                'e': str(self.rsaKey.e),
            },
        }
        for name in ['authentication', 'provisioning']:
            ret[name] = posixpath.join(request.path, name)
        return json.dumps(ret)

class BrowseridAuthenticationResource(Resource):
    def render_GET(self, request):
        try:
            email = furnishRequestEmail(request)
        except UnverifiedPeer:
            email = None
        root = tags.head(
            tags.script(src='https://login.persona.org/authentication_api.js'),
            tags.script('var cert_email = %s;' % (json.dumps(email),)),
            tags.script(AUTHENTICATION_JS))
        return renderElement(request, root)

class BrowseridProvisioningResource(Resource):
    def __init__(self, rsaKey):
        Resource.__init__(self)
        self.rsaKey = rsaKey

    def render_GET(self, request):
        root = tags.head(
            tags.script(src='https://login.persona.org/provisioning_api.js'),
            tags.script('navigator.id.raiseProvisioningFailure("user is not authenticated as target user")'))
        return renderElement(request, root)
