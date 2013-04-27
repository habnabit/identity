from twisted.web.resource import Resource

import json


class WhoamiResource(Resource):
    def _asJSON(self, request):
        if not request.isSecure():
            return {'status': 'unverified', 'reason': 'no-https'}

        cert = request.transport.getPeerCertificate()
        if not cert:
            return {'status': 'unverified', 'reason': 'no-cert'}

        components = dict(cert.get_subject().get_components())
        if 'emailAddress' not in components:
            return {'status': 'unverified', 'reason': 'no-email'}

        return {'status': 'verified', 'email': components['emailAddress']}

    def render_GET(self, request):
        request.setHeader('content-type', 'application/json')
        ret = self._asJSON(request)
        return json.dumps(ret)
