package net.openid.conformance.fapi2baselineid2;

import com.google.gson.JsonObject;
import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.client.*;
import net.openid.conformance.testmodule.PublishTestModule;
import net.openid.conformance.variant.VariantNotApplicable;

//PAR-2.2.1 : The request_uri MUST be bound to the client that posted the authorization request.
@PublishTestModule(
	testName = "fapi2-baseline-id2-par-attempt-to-use-request_uri-for-different-client",
	displayName = "PAR : try to use request_uri from client1 for client2",
	summary = "This test tries to use a request_uri (meant for client1) with client2 and expects authorization server to return an  error",
	profile = "FAPI2-Baseline-ID2",
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
		"resource.resourceUrl"
	}
)
public class FAPI2BaselineID2PAREnsureRequestUriIsBoundToClient extends AbstractFAPI2BaselineID2ServerTestModule {

	@Override
	protected void onConfigure(JsonObject config, String baseUrl) {
		super.onConfigure(config, baseUrl);
		allowPlainErrorResponseForJarm = true;
	}

	@Override
	protected void configureClient() {
		super.configureClient();
		configureSecondClient();
	}

	@Override
	protected void performPARRedirectWithRequestUri() {
		eventLog.startBlock("Attempting to send client2's clientId with request_uri to AS and expect it returns error in callback");

		switchToSecondClient();
		callAndStopOnFailure(AddClientIdToAuthorizationEndpointRequest.class, "PAR-2.2.1");

		callAndStopOnFailure(BuildRequestObjectByReferenceRedirectToAuthorizationEndpoint.class);

		performRedirectAndWaitForPlaceholdersOrCallback();
	}

	@Override
	protected void createPlaceholder() {
		callAndStopOnFailure(ExpectInvalidRequestUriErrorPage.class, "PAR-3-3");

		env.putString("error_callback_placeholder", env.getString("request_uri_invalid_error"));

		eventLog.endBlock();
	}

	@Override
	protected void onAuthorizationCallbackResponse() {

		verifyError();

		eventLog.endBlock();

		fireTestFinished();
	}

	protected void verifyError() {
		callAndContinueOnFailure(EnsureInvalidRequestInvalidRequestObjectOrInvalidRequestUriError.class, Condition.ConditionResult.FAILURE, "PAR-3-3");
	}

}
