/* ── Helpers ── */

function isEmail(value) {
    return /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(value);
}

/* Remove every HTML tag and the most dangerous characters from a string */
function stripTags(value) {
    return value
        .replace(/<[^>]*>/g, '')          /* strip HTML tags           */
        .replace(/[<>"'`\\]/g, '');        /* strip remaining delimiters */
}

/* Reject strings that look like SQL injection attempts */
function hasSqlInjection(value) {
    return /('|--|;|\/\*|\*\/|xp_|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b|\bEXEC\b|\bUNION\b|\bOR\b\s+[\d'"]|\bAND\b\s+[\d'"])/i
        .test(value);
}

/* Only letters, spaces, hyphens and accented characters – for names */
function isValidName(value) {
    return /^[a-zA-ZÀ-ÖØ-öø-ÿ' \-]{3,50}$/.test(value);
}

/* Only letters, spaces, hyphens, numbers – for city names */
function isValidCity(value) {
    return value === '' || /^[a-zA-ZÀ-ÖØ-öø-ÿ0-9' \-,.]{0,50}$/.test(value);
}

/* ── Main validator ── */

function LocalFormValidator() {

    /* ── 1. Honeypot – must stay empty ── */
    var hp = document.getElementById('_hp');
    if (hp && hp.value !== '') {
        return false;
    }

    /* ── 2. Timing check – minimum 4 seconds on page ── */
    if (window._formLoadTime && (Date.now() - window._formLoadTime) < 4000) {
        return false;
    }

    /* ── 3. Civilité ── */
    var title = document.querySelector('input[name="TITLE"]:checked');
    if (!title) {
        alert("S'il vous plaît entrez votre civilité.");
        return false;
    }

    /* ── 4. Prénom ── */
    var firstname = stripTags(document.formulaire.FIRSTNAME.value.trim());
    if (!isValidName(firstname)) {
        alert("Entrez votre prénom s'il vous plait (3 caractères minimum, lettres uniquement).");
        document.formulaire.FIRSTNAME.focus();
        return false;
    }
    if (hasSqlInjection(firstname)) {
        alert("Entrez votre prénom s'il vous plait.");
        document.formulaire.FIRSTNAME.focus();
        return false;
    }

    /* ── 5. Nom ── */
    var nom = stripTags(document.formulaire.LASTNAME.value.trim());
    if (!isValidName(nom)) {
        alert("Entrez votre nom s'il vous plait (3 caractères minimum, lettres uniquement).");
        document.formulaire.LASTNAME.focus();
        return false;
    }
    if (hasSqlInjection(nom)) {
        alert("Entrez votre nom s'il vous plait.");
        document.formulaire.LASTNAME.focus();
        return false;
    }

    /* ── 6. Email ── */
    var email = document.formulaire.EMAIL.value.trim().toLowerCase();
    if (!email) {
        alert("S'il vous plaît,mettez une adresse email valide.");
        document.formulaire.EMAIL.focus();
        return false;
    }
    if (!isEmail(email)) {
        alert("S'il vous plaît,mettez une adresse email valide.");
        document.formulaire.EMAIL.focus();
        return false;
    }

    /* ── 7. Confirmation email ── */
    var emailConfirm = document.formulaire.EMAIL_CONFIRM.value.trim().toLowerCase();
    if (!emailConfirm) {
        alert("S'il vous plaît confirmer votre adresse.");
        document.formulaire.EMAIL_CONFIRM.focus();
        return false;
    }
    if (email !== emailConfirm) {
        alert("S'il vous plaît confirmer votre adresse.");
        document.formulaire.EMAIL_CONFIRM.focus();
        return false;
    }

    /* ── 8. Date de naissance ── */
    var day   = document.formulaire.DAY_BIRTHDAY.value;
    var month = document.formulaire.MONTH_BIRTHDAY.value;
    var year  = document.formulaire.YEAR_BIRTHDAY.value;

    if (day === '0' || month === '0' || year === '0') {
        alert("Entrez une date de naissance valide.");
        return false;
    }

    var birthDate = new Date(parseInt(year, 10), parseInt(month, 10) - 1, parseInt(day, 10));
    var today     = new Date();
    var age       = today.getFullYear() - birthDate.getFullYear();
    var m         = today.getMonth() - birthDate.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
        age--;
    }
    if (isNaN(age) || age < 18 || age > 120) {
        alert("Entrez une date de naissance valide.");
        return false;
    }

    /* ── 9. Ville de naissance (optional) ── */
    var city1 = stripTags(document.formulaire.CITY1.value.trim());
    if (!isValidCity(city1) || hasSqlInjection(city1)) {
        alert("Entrez une ville de naissance valide.");
        document.formulaire.CITY1.focus();
        return false;
    }

    /* ── 10. Ville de résidence (optional) ── */
    var city = stripTags(document.formulaire.CITY.value.trim());
    if (!isValidCity(city) || hasSqlInjection(city)) {
        alert("Entrez une ville valide.");
        document.formulaire.CITY.focus();
        return false;
    }

    /* ── 11. Checkbox 18+ ── */
    if (!document.formulaire.majeur.checked) {
        alert("Veuillez certifier que vous avez plus de 18 ans");
        return false;
    }

    /* ── Write sanitized values back before submit ── */
    document.formulaire.FIRSTNAME.value    = firstname;
    document.formulaire.LASTNAME.value     = nom;
    document.formulaire.EMAIL.value        = email;
    document.formulaire.EMAIL_CONFIRM.value = emailConfirm;
    document.formulaire.CITY1.value        = city1;
    document.formulaire.CITY.value         = city;

    if (window.grecaptcha && window.RECAPTCHA_SITE_KEY) {
        grecaptcha.ready(function () {
            grecaptcha.execute(window.RECAPTCHA_SITE_KEY, { action: 'contact' }).then(function (token) {
                document.getElementById('g-recaptcha-response').value = token;
                document.formulaire.submit();
            });
        });
    } else {
        document.formulaire.submit();
    }
    return false;
}
