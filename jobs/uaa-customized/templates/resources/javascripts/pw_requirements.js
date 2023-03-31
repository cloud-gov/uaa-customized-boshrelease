$(document).ready(function(){
  // Get all the password policy requirements.
  // In case the policy equals to null, initialize the values to 0.
  var lengthCount = <%= p("uaa.password.policy.minLength") %>;
  var passwordField = "password";
  var confirmPasswordField = "password_confirmation";
  var submitButton = "submit";
  validatePassword(lengthCount,
                    passwordField,
                    confirmPasswordField,
                    submitButton
                  );
});