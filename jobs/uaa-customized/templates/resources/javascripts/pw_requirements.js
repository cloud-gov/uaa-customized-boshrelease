$(document).ready(function(){
  // Get all the password policy requirements.
  // In case the policy equals to null, initialize the values to 0.
  var lengthCount = <%= p("uaa.password.policy.minLength") %>;
  var passwordField = document.getElementsByName("password")[0].value
  var confirmPasswordField = document.getElementsByName("password_confirmation")[0].value;
  var submitButton = document.getElementsByName("submit")[0].value;
  validatePassword(lengthCount,
                    passwordField,
                    confirmPasswordField,
                    submitButton
                  );
});