package co.codestra.keycloak.moneybee;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;

public final class MoneyBeeEmailOtpRequiredAction implements RequiredActionProvider, RequiredActionFactory {
    public static final String PROVIDER_ID = "moneybee-verify-email-otp";

    private static final String HASH_NOTE = "moneybee_email_otp_hash";
    private static final String EXPIRES_NOTE = "moneybee_email_otp_expires";
    private static final String ATTEMPTS_NOTE = "moneybee_email_otp_attempts";

    // Send throttling must survive a restarted browser/login flow. Authentication
    // session notes are intentionally not used for these counters because a new
    // authentication session would reset them. These internal attributes are not
    // mapped into MoneyBee tokens or downstream events.
    private static final String LAST_SENT_ATTRIBUTE = "moneybee.security.emailOtp.lastSent";
    private static final String SENDS_ATTRIBUTE = "moneybee.security.emailOtp.sends";
    private static final String WINDOW_ATTRIBUTE = "moneybee.security.emailOtp.window";

    private static final int TTL_SECONDS = 600;
    private static final int MAX_ATTEMPTS = 5;
    private static final int RESEND_COOLDOWN_SECONDS = 60;
    private static final int MAX_SENDS_PER_HOUR = 5;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        // The borrower registration gate explicitly adds this action after a new
        // MoneyBee borrower account is created. Do not trigger it realm-wide.
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (context.getUser().isEmailVerified()) {
            clearSessionCode(context.getAuthenticationSession());
            context.success();
            return;
        }
        try {
            ensureCode(context, false);
            context.challenge(form(context, null));
        } catch (RuntimeException | EmailException exc) {
            context.failure("email_verification_unavailable");
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String action = context.getHttpRequest().getDecodedFormParameters().getFirst("action");
        if ("resend".equals(action)) {
            try {
                long now = Instant.now().getEpochSecond();
                long lastSent = longUserAttribute(context.getUser(), LAST_SENT_ATTRIBUTE, 0);
                if (lastSent > 0 && now - lastSent < RESEND_COOLDOWN_SECONDS) {
                    context.challenge(form(context, "Wait a moment before requesting another code."));
                    return;
                }
                ensureCode(context, true);
                context.challenge(form(context, "A new verification code was sent."));
            } catch (RuntimeException | EmailException exc) {
                context.challenge(form(context, "A new code could not be sent right now."));
            }
            return;
        }

        String code = context.getHttpRequest().getDecodedFormParameters().getFirst("code");
        if (code == null || !code.matches("^[0-9]{6}$")) {
            context.challenge(form(context, "Enter the 6-digit code from your email."));
            return;
        }

        long now = Instant.now().getEpochSecond();
        long expires = longNote(authSession, EXPIRES_NOTE, 0);
        String expected = authSession.getAuthNote(HASH_NOTE);
        int attempts = intNote(authSession, ATTEMPTS_NOTE, 0);
        if (expected == null || expires <= now) {
            context.challenge(form(context, "This code expired. Request a new code."));
            return;
        }
        if (attempts >= MAX_ATTEMPTS) {
            context.challenge(form(context, "Too many attempts. Request a new code."));
            return;
        }

        authSession.setAuthNote(ATTEMPTS_NOTE, Integer.toString(attempts + 1));
        if (!constantTimeEquals(expected, hash(context.getUser().getId(), code))) {
            context.challenge(form(context, attempts + 1 >= MAX_ATTEMPTS
                ? "Too many attempts. Request a new code."
                : "That code is not correct."));
            return;
        }

        context.getUser().setEmailVerified(true);
        clearSessionCode(authSession);
        context.success();
    }

    private static jakarta.ws.rs.core.Response form(RequiredActionContext context, String info) {
        long now = Instant.now().getEpochSecond();
        long expires = longNote(context.getAuthenticationSession(), EXPIRES_NOTE, 0);
        long lastSent = longUserAttribute(context.getUser(), LAST_SENT_ATTRIBUTE, 0);
        long resendWait = Math.max(0, RESEND_COOLDOWN_SECONDS - Math.max(0, now - lastSent));
        var form = context.form()
            .setAttribute("maskedEmail", maskEmail(context.getUser().getEmail()))
            .setAttribute("expiresInSeconds", Math.max(0, expires - now))
            .setAttribute("resendWaitSeconds", resendWait);
        if (info != null) {
            form.setAttribute("moneybeeOtpMessage", info);
        }
        return form.createForm("moneybee-email-otp.ftl");
    }

    private static void ensureCode(RequiredActionContext context, boolean force) throws EmailException {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        UserModel user = context.getUser();
        long now = Instant.now().getEpochSecond();
        long expires = longNote(authSession, EXPIRES_NOTE, 0);
        if (!force && authSession.getAuthNote(HASH_NOTE) != null && expires > now) {
            return;
        }

        long window = longUserAttribute(user, WINDOW_ATTRIBUTE, 0);
        int sends = intUserAttribute(user, SENDS_ATTRIBUTE, 0);
        if (window == 0 || now - window >= 3600) {
            window = now;
            sends = 0;
        }
        if (sends >= MAX_SENDS_PER_HOUR) {
            throw new IllegalStateException("email OTP send limit exceeded");
        }

        String code = String.format("%06d", RANDOM.nextInt(1_000_000));
        context.getSession().getProvider(EmailTemplateProvider.class)
            .setAuthenticationSession(authSession)
            .setRealm(context.getRealm())
            .setUser(user)
            .send(
                "moneybeeEmailOtpSubject",
                "moneybee-email-otp.ftl",
                Map.of("code", code, "expiresInMinutes", TTL_SECONDS / 60)
            );

        // Only make a successfully submitted code usable and count it against
        // the user-persistent quota after the SECURITY email provider accepted it.
        authSession.setAuthNote(HASH_NOTE, hash(user.getId(), code));
        authSession.setAuthNote(EXPIRES_NOTE, Long.toString(now + TTL_SECONDS));
        authSession.setAuthNote(ATTEMPTS_NOTE, "0");
        user.setSingleAttribute(LAST_SENT_ATTRIBUTE, Long.toString(now));
        user.setSingleAttribute(WINDOW_ATTRIBUTE, Long.toString(window));
        user.setSingleAttribute(SENDS_ATTRIBUTE, Integer.toString(sends + 1));
    }

    private static String hash(String userId, String code) {
        String secret = System.getenv("MONEYBEE_EMAIL_OTP_HMAC_KEY");
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException("MONEYBEE_EMAIL_OTP_HMAC_KEY must be at least 32 characters");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getEncoder().encodeToString(mac.doFinal((userId + "\n" + code).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exc) {
            throw new IllegalStateException("email OTP HMAC unavailable", exc);
        }
    }

    private static boolean constantTimeEquals(String left, String right) {
        return MessageDigest.isEqual(
            left.getBytes(StandardCharsets.US_ASCII),
            right.getBytes(StandardCharsets.US_ASCII)
        );
    }

    private static long longNote(AuthenticationSessionModel session, String name, long fallback) {
        try {
            String value = session.getAuthNote(name);
            return value == null ? fallback : Long.parseLong(value);
        } catch (NumberFormatException exc) {
            return fallback;
        }
    }

    private static int intNote(AuthenticationSessionModel session, String name, int fallback) {
        try {
            String value = session.getAuthNote(name);
            return value == null ? fallback : Integer.parseInt(value);
        } catch (NumberFormatException exc) {
            return fallback;
        }
    }

    private static long longUserAttribute(UserModel user, String name, long fallback) {
        try {
            String value = user.getFirstAttribute(name);
            return value == null ? fallback : Long.parseLong(value);
        } catch (NumberFormatException exc) {
            return fallback;
        }
    }

    private static int intUserAttribute(UserModel user, String name, int fallback) {
        try {
            String value = user.getFirstAttribute(name);
            return value == null ? fallback : Integer.parseInt(value);
        } catch (NumberFormatException exc) {
            return fallback;
        }
    }

    private static String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "your email address";
        String[] parts = email.split("@", 2);
        String local = parts[0];
        String masked = local.length() <= 2 ? "**" : local.substring(0, 2) + "***";
        return masked + "@" + parts[1];
    }

    private static void clearSessionCode(AuthenticationSessionModel session) {
        session.removeAuthNote(HASH_NOTE);
        session.removeAuthNote(EXPIRES_NOTE);
        session.removeAuthNote(ATTEMPTS_NOTE);
    }

    @Override public RequiredActionProvider create(KeycloakSession session) { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayText() { return "Verify email with MoneyBee code"; }
    @Override public boolean isOneTimeAction() { return true; }
    @Override public boolean isConfigurable() { return false; }
    @Override public List<ProviderConfigProperty> getConfigMetadata() { return List.of(); }
}
