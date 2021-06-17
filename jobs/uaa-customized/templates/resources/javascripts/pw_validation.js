/* exported validatePassword */
/* global zxcvbn */
// validatePassword contains the logic for client side password validation.
// It is passed in rule threshold information and then sets up watchers to check
// the password as it is typed in. It then compares the password to the value
// of the confirmation password.
// This function is to be used in with the html from pw_validation.html
function validatePassword(lengthCount, passwordField,
                            confirmPasswordField, submitButton) {
    // Set the values for the password policy requirements into the html.
    document.getElementById("length-count").innerText=''+lengthCount+'';

    // Set markers to dictate whether or not to check a particular rule. Default to true.
    var lengthRule = true;

    // Hide rules that aren't set or set to zero. Set the markers to false to indicate not to check them.
    if ( lengthCount === 0 ) {
        $('#length-req').hide();
        lengthRule = false;
    }

    // Create a simple boolean to check if no policy is set.
    var noRules = (lengthCount === 0);
    // If no policy, make sure it stays hidden.
    if (noRules == true) {$('#password-requirements').hide();}

    // validateField is a helper function.
    // Depending on the current conditional, it will set the CSS class for the
    // corresponding 'html_field' text to either 'text-success' or 'text-danger'
    // Returns whether it is valid.
    // Returns true if field is valid. Else, false.
    function validateField(errorCase, htmlField) {
        if ( errorCase === true ) {
            $(htmlField).removeClass('text-success').addClass('text-danger');
            return false;
        } else {
            $(htmlField).removeClass('text-danger').addClass('text-success');
            return true;
        }
    }

    // compareNewPasswords is a helper function.
    // It will look at the values of passwordField and confirmPasswordField
    // and compare them. If equal, it will set a placeholder text to read 'DO'.
    // Else, it will be set to 'DO NOT'.
    // This placeholder text will either fit in a broader text to either read:
    // "Passwords 'DO/ DO NOT' match."
    // Return true if passwords match; false if passwords do not match.
    function compareNewPasswords() {
        // Get the password value.
        var pw = $("input[type='password'][name='" + passwordField + "']").val();
        // Get the confirm password value.
        var confirmPw = $("input[type='password'][name='" + confirmPasswordField + "']").val();
        if (pw === confirmPw) {
            document.getElementById("match-passwords").innerText='DO';
            return true;
        }
        document.getElementById("match-passwords").innerText='DO NOT';
        return false;
    }

    // Get the zxcvbn data and filter out only what we need
    function zxcvbnData(password) {
        var zxcvbnResult = zxcvbn(password);
        return {
            score: zxcvbnResult.score,
            feedback: zxcvbnResult.feedback.warning,
        };
    }

    // validateFields returns whether or not all available fields are valid.
    function validateFields() {
        // If no rules, no need to do anything else.
        if ( noRules == true ) {return true;}

        // Get the password value.
        var pw = $("input[type='password'][name='" + passwordField + "']").val();

        // Validate the length of the password.
        var validLength = (lengthRule ? (validateField( ( pw.length < lengthCount ), '#length-req')) : true);

        // if there is a warning, it will get put in zxcvbnResultId
        var zxcvbnResult = zxcvbnData(pw);
        var zxcvbnResultId = "#zxcvbn-req";
        $(zxcvbnResultId).text(zxcvbnResult.feedback);
        var validResult = validateField((zxcvbnResult.score < 3), zxcvbnResultId);

        return validLength && validResult;
    }

    // enableSubmitButton enables the submit button.
    function enableSubmitButton() {
        $("input[type='submit'][name='" + submitButton + "']").attr('disabled' , false);
    }

    // disableSubmitButton disables the submit button.
    function disableSubmitButton() {
        $("input[type='submit'][name='" + submitButton + "']").attr('disabled' , true);
    }

    // checkPasswords is a wrapper function.
    // It checks for equal passwords and the password rules.
    // It will show the information for each in case they are invalid
    function checkPasswords() {
        // Compare new passwords.
        var equalPw = compareNewPasswords();
        // Check if field rules are valid.
        var validatedRules = validateFields();
        if (equalPw && validatedRules) {
            // Everything is right. Enable the submit button.
            enableSubmitButton();
            // Hide password equal box.
            $('#pw-confirm-requirement').hide();
            // Hide rules box.
            $('#password-requirements').hide();
        } else if (!equalPw && validatedRules) {
            // Unequal password but valid rules.
            // Make sure the submit button is disabled.
            disableSubmitButton();
            // Show password equal box.
            $('#pw-confirm-requirement').show();
            // Hide rules box.
            $('#password-requirements').hide();
        } else if (equalPw && !validatedRules) {
            // Equal password but invalid rules.
            // Make sure the submit button is disabled.
            disableSubmitButton();
            // Hide password equal box.
            $('#pw-confirm-requirement').hide();
            // Show rules box.
            $('#password-requirements').show();
        } else {
            // Unequal password AND invalid rules.
            // Make sure the submit button is disabled.
            disableSubmitButton();
            // Show password equal box.
            $('#pw-confirm-requirement').show();
            // Show rules box.
            $('#password-requirements').show();
        }
    }

    // Setup password validator.
    $("input[type='password'][name='" + passwordField + "']").bind("change keyup", function() {
        checkPasswords();
    });

    // Setup matcher for password confirmation.
    $("input[type='password'][name='" + confirmPasswordField + "']").keyup(function() {
        checkPasswords();
    });

    // Call checkPasswords for the first time.
    checkPasswords();
}
