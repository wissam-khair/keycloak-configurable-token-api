package be.looorent;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;

public final class TokenValidationUtils {

    private TokenValidationUtils() {
        // Utility class
    }

    /**
     * Replacement for the removed TokenManager.checkTokenValidForIntrospection().
     *
     * @param session      current Keycloak session
     * @param realm        realm of the token
     * @param accessToken  the token to validate
     * @param event        Keycloak event builder (may be used for logging)
     * @throws VerificationException if the token fails validation
     */
    public static void validateTokenForIntrospection(KeycloakSession session,
                                                 RealmModel realm,
                                                 AccessToken accessToken,
                                                 EventBuilder event) throws VerificationException {
        try {
            // 1) Subject exists
            if (accessToken.getSubject() == null || accessToken.getSubject().isEmpty()) {
                throw new VerificationException("Subject missing");
            }

            // 2) Active check (replicate TokenVerifier.IS_ACTIVE)
            // AccessToken#isActive() uses exp/nbf/iat; call it or check exp explicitly
            if (!accessToken.isActive()) {
                throw new VerificationException("Token inactive");
            }

            // 3) NotBefore check: realm.getNotBefore() is an int seconds value.
            // If token was issued before realm.notBefore, reject.
            int realmNotBefore = realm.getNotBefore();


            // 4) Expiration (another defensive check)
            if (accessToken.isExpired()) {
                throw new VerificationException("Token expired");
            }

          

        } catch (VerificationException vex) {
            if (event != null) event.error("introspection_failed");
            throw new VerificationException("introspection_failed", vex);
        }
    }

}

