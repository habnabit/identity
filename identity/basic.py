from OpenSSL.crypto import FILETYPE_PEM, load_certificate
from twisted.web.resource import Resource

import json


class UnverifiedPeer(Exception):
    pass


class PeerVerifier(object):
    def __init__(self, acceptCertAsHeader=False):
        self.acceptCertAsHeader = acceptCertAsHeader

    def furnishRequestEmail(self, request):
        if not request.isSecure():
            if not self.acceptCertAsHeader:
                raise UnverifiedPeer('no-https')
            pem = request.getHeader('X-SSL-Client-Cert')
            if not pem:
                raise UnverifiedPeer('no-http-header')
            pem = '\n'.join(line.strip() for line in pem.splitlines())
            cert = load_certificate(FILETYPE_PEM, pem)
        else:
            cert = request.transport.getPeerCertificate()

        if not cert:
            raise UnverifiedPeer('no-cert')

        components = dict(cert.get_subject().get_components())
        if 'emailAddress' not in components:
            raise UnverifiedPeer('no-email')

        return components['emailAddress']


class WhoamiResource(Resource):
    def __init__(self, verifier):
        Resource.__init__(self)
        self.verifier = verifier

    def _asJSON(self, request):
        try:
            email = self.verifier.furnishRequestEmail(request)
        except UnverifiedPeer as e:
            return {'status': 'unverified', 'reason': e.args[0]}
        else:
            return {'status': 'verified', 'email': email}

    def render_GET(self, request):
        request.setHeader('content-type', 'application/json')
        ret = self._asJSON(request)
        return json.dumps(ret)
