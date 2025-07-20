document.addEventListener("DOMContentLoaded", function () {
    const siteKeyMeta = document.querySelector('meta[name="recaptcha-site-key"]');
    if (typeof executeRecaptcha === "function" && siteKeyMeta) {
        executeRecaptcha(siteKeyMeta.content);
    } else {
        console.warn("reCAPTCHA not initialized: executeRecaptcha() missing or site key not found.");
    }
});
