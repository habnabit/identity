var xhr = new XMLHttpRequest();

navigator.id.beginProvisioning(function (persona_email, cert_duration) {
  if (cert_email != persona_email) {
    navigator.id.raiseProvisioningFailure('user is not authenticated as target user');
    return;
  }
  navigator.id.genKeyPair(function (public_key) {
    public_key = JSON.parse(public_key);
    var payload = {'key': public_key, 'email': persona_email, 'duration': cert_duration};
    xhr.open('POST', document.location.href, false);
    xhr.send(JSON.stringify(payload));
    if (xhr.status != 200) {
      navigator.id.raiseProvisioningFailure("couldn't sign key");
      return;
    }
    navigator.id.registerCertificate(xhr.responseText);
  });
});
