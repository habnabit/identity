from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

from twisted.python.filepath import FilePath
from twisted.web.resource import Resource
from twisted.web.template import tags, renderElement

from identity.basic import UnverifiedPeer

import base64
import json
import posixpath
import time


JS = {}
for name in ['authentication.js', 'provisioning.js']:
    with FilePath(__file__).sibling('js').child(name).open() as infile:
        JS[name] = infile.read()


def b64uencode(s):
    return base64.urlsafe_b64encode(str(s)).replace('=', '')

def sign(payload, key):
    encoded_header = b64uencode(json.dumps({'alg': 'RS256'}))
    signing_input = encoded_header + '.' + b64uencode(json.dumps(payload))
    signature = PKCS1_v1_5.new(key).sign(SHA256.new(signing_input))
    return signing_input + '.' + b64uencode(signature)

def certEmailScriptTag(verifier, request):
    try:
        email = verifier.furnishRequestEmail(request)
    except UnverifiedPeer:
        email = None
    return tags.script('var cert_email = %s;' % (json.dumps(email),))


class BrowseridResource(Resource):
    def __init__(self, rsaKey, verifier):
        Resource.__init__(self)
        self.rsaKey = rsaKey
        self.verifier = verifier
        self.putChild('authentication', BrowseridAuthenticationResource(verifier))
        self.putChild('provisioning', BrowseridProvisioningResource(self.rsaKey, verifier))

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
    def __init__(self, verifier):
        Resource.__init__(self)
        self.verifier = verifier

    def render_GET(self, request):
        root = tags.head(
            tags.script(src='https://login.persona.org/authentication_api.js'),
            certEmailScriptTag(self.verifier, request),
            tags.script(JS['authentication.js']))
        return renderElement(request, root)

class BrowseridProvisioningResource(Resource):
    def __init__(self, rsaKey, verifier):
        Resource.__init__(self)
        self.rsaKey = rsaKey
        self.verifier = verifier

    def render_GET(self, request):
        root = tags.head(
            tags.script(src='https://login.persona.org/provisioning_api.js'),
            certEmailScriptTag(self.verifier, request),
            tags.script(JS['provisioning.js']))
        return renderElement(request, root)

    def render_POST(self, request):
        parameters = json.load(request.content)
        email = self.verifier.furnishRequestEmail(request)
        assert parameters['email'] == email
        now = int(time.time())
        token = {
            'public-key': parameters['key'],
            'principal': {'email': email},
            'iat': now * 1000,
            'exp': (now + min(60 * 60, parameters['duration'])) * 1000,
            'iss': request.getRequestHostname(),
        }
        return sign(token, self.rsaKey)
