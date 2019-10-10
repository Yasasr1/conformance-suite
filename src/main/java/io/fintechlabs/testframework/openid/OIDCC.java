package io.fintechlabs.testframework.openid;

import io.fintechlabs.testframework.condition.Condition;
import io.fintechlabs.testframework.condition.client.CallProtectedResourceWithBearerTokenExpectingError;
import io.fintechlabs.testframework.condition.client.CallTokenEndpointAndReturnFullResponse;
import io.fintechlabs.testframework.condition.client.CheckErrorFromTokenEndpointResponseErrorInvalidGrant;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointHttpStatus400;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointReturnedJsonContentType;
import io.fintechlabs.testframework.condition.client.ValidateErrorDescriptionFromTokenEndpointResponseError;
import io.fintechlabs.testframework.condition.client.ValidateErrorFromTokenEndpointResponseError;
import io.fintechlabs.testframework.condition.client.ValidateErrorUriFromTokenEndpointResponseError;
import io.fintechlabs.testframework.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "oidcc",
	displayName = "OIDCC: Authorization server test",
	summary = "This test uses two different OAuth clients, authenticates the user twice (using different variations on registered redirect uri etc), and tries reusing an authorization code.",
	profile = "OIDCC",
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.scope",
		"client2.client_id",
		"client2.scope",
		"resource.resourceUrl"
	}
)
public class OIDCC extends AbstractOIDCCMultipleClient {

	@Override
	protected void performSecondClientTests() {
		if (responseType.includesCode()) {
			testReuseOfAuthorizationCode();
		}
	}

	private void testReuseOfAuthorizationCode() {
		eventLog.startBlock("Attempting reuse of client2's authorisation code & testing if access token is revoked");
		callAndContinueOnFailure(CallTokenEndpointAndReturnFullResponse.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(CheckTokenEndpointHttpStatus400.class, Condition.ConditionResult.FAILURE, "OIDCC-3.1.3.4");
		callAndContinueOnFailure(CheckTokenEndpointReturnedJsonContentType.class, Condition.ConditionResult.FAILURE, "OIDCC-3.1.3.4");
		callAndContinueOnFailure(CheckErrorFromTokenEndpointResponseErrorInvalidGrant.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
		callAndContinueOnFailure(ValidateErrorFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
		callAndContinueOnFailure(ValidateErrorDescriptionFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
		callAndContinueOnFailure(ValidateErrorUriFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");

		// The AS 'SHOULD' have revoked the access token; try it again".
		callAndContinueOnFailure(CallProtectedResourceWithBearerTokenExpectingError.class, Condition.ConditionResult.WARNING, "RFC6749-4.1.2");
		eventLog.endBlock();
	}
}
