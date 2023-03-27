$(document).ready(function(){
    // Get all the password policy requirements.
    // In case the policy equals to null, initialize the values to 0.
    var lengthCount = <%= p("uaa.password.policy.minLength") %>;
    validatePassword(lengthCount,
                      /*[[${passwordField}]]*/,
                      /*[[${confirmPasswordField}]]*/,
                      /*[[${submitButton}]]*/
                    );
});