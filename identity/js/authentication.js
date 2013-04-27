navigator.id.beginAuthentication(function (persona_email) {
  document.write('hello, ' + cert_email + '. are you ' + persona_email + '? ');
  document.write(cert_email == persona_email? '(yes.)' : '(no!)');
  window.setTimeout(function () {
    if (cert_email == persona_email) {
      navigator.id.completeAuthentication();
    } else {
      navigator.id.raiseAuthenticationFailure("cert e-mail didn't match");
    }
  }, 2000);
});
