from twisted.web.resource import Resource

import json


class UnverifiedPeer(Exception):
    pass

def furnishRequestEmail(request):
    if not request.isSecure():
        raise UnverifiedPeer('no-https')

    cert = request.transport.getPeerCertificate()
    if not cert:
        raise UnverifiedPeer('no-cert')

    components = dict(cert.get_subject().get_components())
    if 'emailAddress' not in components:
        raise UnverifiedPeer('no-email')

    return components['emailAddress']


class WhoamiResource(Resource):
    def _asJSON(self, request):
        try:
            email = furnishRequestEmail(request)
        except UnverifiedPeer as e:
            return {'status': 'unverified', 'reason': e.args[0]}
        else:
            return {'status': 'verified', 'email': email}

    def render_GET(self, request):
        request.setHeader('content-type', 'application/json')
        ret = self._asJSON(request)
        return json.dumps(ret)
