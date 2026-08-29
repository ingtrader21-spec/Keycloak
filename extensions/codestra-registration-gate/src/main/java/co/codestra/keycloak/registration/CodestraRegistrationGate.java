package co.codestra.keycloak.registration;

import java.util.List;
import java.util.Set;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;

public final class CodestraRegistrationGate implements FormAction, FormActionFactory {
    public static final String PROVIDER_ID = "codestra-registration-gate";

    private static final Set<String> ALLOWED_CLIENT_IDS = Set.of(
        "moneybee-borrower",
        "beyvra-web-production"
    );

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public void validate(ValidationContext context) {
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        if (!ALLOWED_CLIENT_IDS.contains(clientId)) {
            context.error("registration_not_allowed");
            context.validationError(
                context.getHttpRequest().getDecodedFormParameters(),
                List.of(new FormMessage(null, "Registration is not available for this application."))
            );
            return;
        }
        context.success();
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        // Standard Keycloak registration remains the sole credential authority.
    }

    @Override
    public void success(FormContext context) {
        // Realm verifyEmail and standard required actions own email verification.
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getDisplayType() {
        return "Codestra application registration gate";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENTS;
    }

    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Allows public self-registration only for the reviewed MoneyBee borrower and Beyvra browser clients.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
