package net.openid.conformance.openid.client;

import net.openid.conformance.condition.as.AddInvalidAudValueToIdToken;
import net.openid.conformance.condition.client.ExpectOIDCCCallbackWithInvalidAudError;
import net.openid.conformance.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "oidcc-client-test-invalid-aud",
	displayName = "OIDCC: Relying party test. Invalid aud value in id token.",
	summary = "The client must identify that the 'aud' value is incorrect and reject the ID Token after doing ID Token validation." +
		" Corresponds to rp-id_token-aud test in the old test suite",
	profile = "OIDCC",
	configurationFields = {
		"waitTimeoutSeconds"
	}
)
public class OIDCCClientTestInvalidAudInIdToken extends AbstractOIDCCClientTestExpectingNothingInvalidIdToken {

	@Override
	protected void generateIdTokenClaims() {
		super.generateIdTokenClaims();
		callAndStopOnFailure(AddInvalidAudValueToIdToken.class);
	}

	@Override
	protected String getAuthorizationCodeGrantTypeErrorMessage() {
		return "Client has incorrectly called token_endpoint after receiving an id_token with an invalid aud claim from the authorization_endpoint.";
	}

	@Override
	protected String getHandleUserinfoEndpointRequestErrorMessage() {
		return "Client has incorrectly called userinfo_endpoint after receiving an id_token with an invalid aud claim.";
	}

	@Override
	protected void createPlaceholder() {
		callAndStopOnFailure(ExpectOIDCCCallbackWithInvalidAudError.class);
	}

}
