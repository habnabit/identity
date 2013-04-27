navigator.id.beginAuthentication(function (persona_email) {
  if (cert_email == persona_email) {
    navigator.id.completeAuthentication();
  } else {
    navigator.id.raiseAuthenticationFailure("cert e-mail didn't match");
  }
});
