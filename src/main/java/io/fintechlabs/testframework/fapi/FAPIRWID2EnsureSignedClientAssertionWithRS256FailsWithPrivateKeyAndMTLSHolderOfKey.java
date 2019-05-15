package io.fintechlabs.testframework.fapi;

import io.fintechlabs.testframework.condition.Condition;
import io.fintechlabs.testframework.condition.client.AddAlgorithmAsRS256;
import io.fintechlabs.testframework.condition.client.AddClientAssertionToTokenEndpointRequest;
import io.fintechlabs.testframework.condition.client.CallTokenEndpointAndReturnFullResponse;
import io.fintechlabs.testframework.condition.client.CheckErrorFromTokenEndpointResponseErrorInvalidClient;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointHttpStatus401;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointReturnedJsonContentType;
import io.fintechlabs.testframework.condition.client.CreateClientAuthenticationAssertionClaims;
import io.fintechlabs.testframework.condition.client.CreateTokenEndpointRequestForAuthorizationCodeGrant;
import io.fintechlabs.testframework.condition.client.SignClientAuthenticationAssertion;
import io.fintechlabs.testframework.condition.client.ValidateErrorDescriptionFromTokenEndpointResponseError;
import io.fintechlabs.testframework.condition.client.ValidateErrorFromTokenEndpointResponseError;
import io.fintechlabs.testframework.condition.client.ValidateErrorUriFromTokenEndpointResponseError;
import io.fintechlabs.testframework.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "fapi-rw-id2-ensure-signed-client-assertion-with-RS256-fails-with-private-key-and-mtls-holder-of-key",
	displayName = "FAPI-RW-ID2: ensure signed client assertion with RS256 fails (with private key authentication and mtls holder of key)",
	summary = "This test should end with the token endpoint server showing an error message that the signature algorithm of the JWT for client authentication is invalid.",
	profile = "FAPI-RW-ID2",
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.scope",
		"client.jwks",
		"mtls.key",
		"mtls.cert",
		"mtls.ca",
		"client2.client_id",
		"client2.scope",
		"client2.jwks",
		"mtls2.key",
		"mtls2.cert",
		"mtls2.ca",
		"resource.resourceUrl",
		"resource.institution_id"
	}
)
public class FAPIRWID2EnsureSignedClientAssertionWithRS256FailsWithPrivateKeyAndMTLSHolderOfKey extends AbstractFAPIRWID2PerformTokenEndpoint {

	@Override
	protected void createAuthorizationCodeRequest() {

		callAndStopOnFailure(CreateTokenEndpointRequestForAuthorizationCodeGrant.class);

		callAndStopOnFailure(CreateClientAuthenticationAssertionClaims.class);

		callAndStopOnFailure(AddAlgorithmAsRS256.class, "FAPI-RW-8.6");

		callAndStopOnFailure(SignClientAuthenticationAssertion.class);

		callAndStopOnFailure(AddClientAssertionToTokenEndpointRequest.class);

	}

	@Override
	protected void requestAuthorizationCode() {
		/* If we get an error back from the token endpoint server:
		 * - It must be a 'invalid_client' error
		 */
		callAndContinueOnFailure(CallTokenEndpointAndReturnFullResponse.class, Condition.ConditionResult.FAILURE, "FAPI-R-5.2.2-19");
		callAndContinueOnFailure(CheckTokenEndpointHttpStatus401.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
		callAndContinueOnFailure(CheckTokenEndpointReturnedJsonContentType.class, Condition.ConditionResult.FAILURE, "OIDCC-3.1.3.4");
		callAndContinueOnFailure(CheckErrorFromTokenEndpointResponseErrorInvalidClient.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
		callAndContinueOnFailure(ValidateErrorFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
		callAndContinueOnFailure(ValidateErrorDescriptionFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE,"RFC6749-5.2");
		callAndContinueOnFailure(ValidateErrorUriFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE,"RFC6749-5.2");

		fireTestFinished();
	}

}