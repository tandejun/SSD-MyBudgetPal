function executeRecaptcha(siteKey) {
    grecaptcha.ready(function () {
        grecaptcha.execute(siteKey, { action: 'signin' }).then(function (token) {
            const responseField = document.getElementById('g-recaptcha-response');
            if (responseField) {
                responseField.value = token;
            }
        });
    });
}

// Called on form submission to generate a fresh token before sending
function refreshRecaptchaToken() {
    const siteKey = document.querySelector('meta[name="recaptcha-site-key"]')?.content;
    const form = document.querySelector("form[onsubmit*='refreshRecaptchaToken']");

    if (!siteKey || !form) {
        console.warn("reCAPTCHA token or form not found.");
        return true; // allow normal submission if fallback fails
    }

    grecaptcha.ready(function () {
        grecaptcha.execute(siteKey, { action: 'submit' }).then(function (token) {
            const responseField = document.getElementById('g-recaptcha-response');
            if (responseField) {
                responseField.value = token;
                form.submit();
            } else {
                console.warn("reCAPTCHA response field not found.");
                form.submit();
            }
        });
    });

    return false; // block default submission while waiting for token
}

