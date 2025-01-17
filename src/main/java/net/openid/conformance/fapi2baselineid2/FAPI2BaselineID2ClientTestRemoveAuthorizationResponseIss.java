package net.openid.conformance.fapi2baselineid2;

import net.openid.conformance.condition.as.RemoveIssFromAuthorizationEndpointResponseParams;
import net.openid.conformance.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "fapi2-baseline-id2-client-test-remove-authorization-response-iss",
	displayName = "FAPI2-Baseline-ID2: client test - authorization_endpoint response without iss must be rejected",
	summary = "This test does not send an issuer in the authorization response. The client should display a message that the authorization response does not contain an issuer and must not call any other endpoints.",
	profile = "FAPI2-Baseline-ID2",
	configurationFields = {
		"server.jwks",
		"client.client_id",
		"client.scope",
		"client.redirect_uri",
		"client.certificate",
		"client.jwks"
	}
)

public class FAPI2BaselineID2ClientTestRemoveAuthorizationResponseIss extends AbstractFAPI2BaselineID2ClientExpectNothingAfterAuthorizationResponse {
	@Override
	protected String getAuthorizationResponseErrorMessage() {
		return "Removed iss from authorization response";
	}

	@Override
	protected void addCustomValuesToAuthorizationResponse() {
		callAndContinueOnFailure(RemoveIssFromAuthorizationEndpointResponseParams.class);
	}

	@Override
	protected void addCustomValuesToIdToken() {
		// do nothing
	}
}
