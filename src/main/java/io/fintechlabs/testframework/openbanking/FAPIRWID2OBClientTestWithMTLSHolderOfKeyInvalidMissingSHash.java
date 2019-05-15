package io.fintechlabs.testframework.openbanking;

import io.fintechlabs.testframework.condition.Condition;
import io.fintechlabs.testframework.condition.ConditionError;
import io.fintechlabs.testframework.condition.as.RemoveSHashFromIdToken;
import io.fintechlabs.testframework.condition.as.LogEndTestIfStateIsNotSupplied;
import io.fintechlabs.testframework.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "fapi-rw-id2-ob-client-test-with-mtls-holder-of-key-invalid-missing-shash",
	displayName = "FAPI-RW-ID2-OB: client test - missing s_hash value in id_token from authorization_endpoint, should be rejected (with MTLS)",
	summary = "This test should end with the client displaying an error message that the s_hash value in the id_token from the authorization_endpoint is missing",
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

public class FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingSHash extends AbstractFAPIRWID2OBClientMTLSHolderOfKeyExpectNothingAfterAuthorisationEndpoint {

	@Override
	protected boolean endTestIfStateIsNotSupplied() {

		String shash = env.getString("authorization_request_object", "claims.state");
		if (shash == null) {
			callAndContinueOnFailure(LogEndTestIfStateIsNotSupplied.class, Condition.ConditionResult.WARNING);
			fireTestFinished();
			return true;
		}

		return false;
	}

	@Override
	protected void addCustomValuesToIdToken() {

		callAndStopOnFailure(RemoveSHashFromIdToken.class, "FAPI-RW-5.2.3");
	}

	@Override
	protected Object authorizationCodeGrantType(String requestId) {

		throw new ConditionError(getId(), "Client has incorrectly called token_endpoint after receiving an id_token with a missing s_hash value from the authorization_endpoint.");

	}

}