package io.fintechlabs.testframework.openbanking;

import io.fintechlabs.testframework.condition.ConditionError;
import io.fintechlabs.testframework.condition.as.SignIdTokenInvalid;
import io.fintechlabs.testframework.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "fapi-rw-id2-ob-client-test-with-mtls-holder-of-key-invalid-signature",
	displayName = "FAPI-RW-ID2-OB: client test - invalid signature in id_token from authorization_endpoint, should be rejected (with MTLS)",
	summary = "This test should end with the client displaying an error message that the signature in the id_token from the authorization_endpoint does not match the signature value in the request object",
	profile = "FAPI-RW-ID2-OB",
	configurationFields = {
		"server.jwks",
		"client.client_id",
		"client.scope",
		"client.redirect_uri",
		"client.certificate",
		"client.jwks",
	}
)

public class FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidSignature extends AbstractFAPIRWID2OBClientMTLSHolderOfKeyExpectNothingAfterAuthorisationEndpoint {

	@Override
	protected void addCustomValuesToIdToken() {
		//Do Nothing
	}

	@Override
	protected void addCustomSignatureOfIdToken(){

		callAndStopOnFailure(SignIdTokenInvalid.class,"OIDCC-3.1.3.7.6");
	}

	@Override
	protected Object authorizationCodeGrantType(String requestId) {

		throw new ConditionError(getId(), "Client has incorrectly called token_endpoint after receiving an id_token with an invalid signature from the authorization_endpoint.");
	}

}