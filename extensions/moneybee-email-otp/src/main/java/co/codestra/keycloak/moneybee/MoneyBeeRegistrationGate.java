package co.codestra.keycloak.moneybee;

import java.util.List;

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

public final class MoneyBeeRegistrationGate implements FormAction, FormActionFactory {
    public static final String PROVIDER_ID = "moneybee-registration-gate";
    public static final String BORROWER_CLIENT_ID = "moneybee-borrower";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public void validate(ValidationContext context) {
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        if (!BORROWER_CLIENT_ID.equals(clientId)) {
            context.error("registration_not_allowed");
            context.validationError(
                context.getHttpRequest().getDecodedFormParameters(),
                List.of(new FormMessage(null, "Public registration is available only for MoneyBee borrowers."))
            );
            return;
        }
        context.success();
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        // The standard Keycloak registration form remains the credential authority.
    }

    @Override
    public void success(FormContext context) {
        UserModel user = context.getUser();
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        if (
            user != null
            && BORROWER_CLIENT_ID.equals(clientId)
            && !user.isEmailVerified()
        ) {
            user.addRequiredAction(MoneyBeeEmailOtpRequiredAction.PROVIDER_ID);
        }
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
        return "MoneyBee borrower-only registration gate";
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
        return "Rejects realm self-registration unless the initiating OIDC client is moneybee-borrower.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
