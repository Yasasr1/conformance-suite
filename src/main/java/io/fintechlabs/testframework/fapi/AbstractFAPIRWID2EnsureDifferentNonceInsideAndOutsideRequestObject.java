package io.fintechlabs.testframework.fapi;

import com.google.gson.JsonObject;
import io.fintechlabs.testframework.condition.Condition;
import io.fintechlabs.testframework.condition.client.AddExpToRequestObject;
import io.fintechlabs.testframework.condition.client.AddIncorrectNonceToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.BuildRequestObjectRedirectToAuthorizationEndpoint;
import io.fintechlabs.testframework.condition.client.CallProtectedResourceWithBearerTokenAndCustomHeaders;
import io.fintechlabs.testframework.condition.client.CheckForSubjectInIdToken;
import io.fintechlabs.testframework.condition.client.CheckStateInAuthorizationResponse;
import io.fintechlabs.testframework.condition.client.ClearAcceptHeaderForResourceEndpointRequest;
import io.fintechlabs.testframework.condition.client.ConvertAuthorizationEndpointRequestToRequestObject;
import io.fintechlabs.testframework.condition.client.DisallowAccessTokenInQuery;
import io.fintechlabs.testframework.condition.client.EnsureInvalidRequestError;
import io.fintechlabs.testframework.condition.client.ExpectRequestDifferentNonceInsideAndOutsideErrorPage;
import io.fintechlabs.testframework.condition.client.ExtractCHash;
import io.fintechlabs.testframework.condition.client.ExtractIdTokenFromAuthorizationResponse;
import io.fintechlabs.testframework.condition.client.ExtractSHash;
import io.fintechlabs.testframework.condition.client.FAPIValidateIdTokenSigningAlg;
import io.fintechlabs.testframework.condition.client.SetPermissiveAcceptHeaderForResourceEndpointRequest;
import io.fintechlabs.testframework.condition.client.SetPlainJsonAcceptHeaderForResourceEndpointRequest;
import io.fintechlabs.testframework.condition.client.SignRequestObject;
import io.fintechlabs.testframework.condition.client.ValidateCHash;
import io.fintechlabs.testframework.condition.client.ValidateErrorResponseFromAuthorizationEndpoint;
import io.fintechlabs.testframework.condition.client.ValidateIdToken;
import io.fintechlabs.testframework.condition.client.ValidateIdTokenACRClaimAgainstRequest;
import io.fintechlabs.testframework.condition.client.ValidateIdTokenNonce;
import io.fintechlabs.testframework.condition.client.ValidateIdTokenSignature;
import io.fintechlabs.testframework.condition.client.ValidateSHash;
import io.fintechlabs.testframework.condition.common.DisallowInsecureCipher;
import io.fintechlabs.testframework.condition.common.DisallowTLS10;
import io.fintechlabs.testframework.condition.common.DisallowTLS11;
import io.fintechlabs.testframework.condition.common.EnsureTLS12;

public abstract class AbstractFAPIRWID2EnsureDifferentNonceInsideAndOutsideRequestObject extends AbstractFAPIRWID2ServerTestModule {

	@Override
	protected void performAuthorizationFlow() {

		createAuthorizationRequest();

		createAuthorizationRedirect();

		performRedirectAndWaitForErrorCallback();
	}

	@Override
	protected void createPlaceholder() {
		callAndStopOnFailure(ExpectRequestDifferentNonceInsideAndOutsideErrorPage.class, "OIDCC-6.1");

		env.putString("error_callback_placeholder", "request_unverifiable_error");
	}

	@Override
	protected void createAuthorizationRedirect() {
		callAndStopOnFailure(ConvertAuthorizationEndpointRequestToRequestObject.class);

		callAndStopOnFailure(AddExpToRequestObject.class);

		callAndStopOnFailure(SignRequestObject.class);

		callAndStopOnFailure(AddIncorrectNonceToAuthorizationEndpointRequest.class, "OIDCC-6.1");

		callAndStopOnFailure(BuildRequestObjectRedirectToAuthorizationEndpoint.class);
	}

	@Override
	protected void onAuthorizationCallbackResponse() {
		// We now have callback_query_params and callback_params (containing the hash) available, as well as authorization_endpoint_response (which test conditions should use if they're looking for the response)
		JsonObject callbackParams = env.getObject("authorization_endpoint_response");

		if (!callbackParams.has("error")) {

			super.onAuthorizationCallbackResponse();

		} else {
			/* If we get an error back from the authorisation server:
			 * - It must be a 'invalid_request' error
			 * - It must have the correct state we supplied
			 */

			callAndContinueOnFailure(CheckStateInAuthorizationResponse.class, Condition.ConditionResult.FAILURE);
			callAndContinueOnFailure(ValidateErrorResponseFromAuthorizationEndpoint.class, Condition.ConditionResult.FAILURE, "OIDCC-3.1.2.6");
			callAndContinueOnFailure(EnsureInvalidRequestError.class, Condition.ConditionResult.FAILURE, "OIDCC-3.3.2.6");
			fireTestFinished();
		}
	}

	@Override
	protected void performPostAuthorizationFlow() {
		callAndStopOnFailure(ExtractIdTokenFromAuthorizationResponse.class, "FAPI-RW-5.2.2-3");

		// save the id_token returned from the authorisation endpoint
		env.putObject("authorization_endpoint_id_token", env.getObject("id_token"));

		callAndStopOnFailure(ValidateIdToken.class, "FAPI-RW-5.2.2-3");

		callAndStopOnFailure(ValidateIdTokenNonce.class, "OIDCC-2");

		callAndContinueOnFailure(ValidateIdTokenACRClaimAgainstRequest.class, Condition.ConditionResult.FAILURE, "OIDCC-5.5.1.1");

		performProfileIdTokenValidation();

		callAndStopOnFailure(ValidateIdTokenSignature.class, "FAPI-RW-5.2.2-3");

		callAndStopOnFailure(CheckForSubjectInIdToken.class, "FAPI-R-5.2.2-24", "OB-5.2.2-8");
		callAndContinueOnFailure(FAPIValidateIdTokenSigningAlg.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.6");

		callAndContinueOnFailure(ExtractSHash.class, Condition.ConditionResult.FAILURE, "FAPI-RW-5.2.2-4");

		skipIfMissing(new String[]{"s_hash"}, null, Condition.ConditionResult.INFO,
			ValidateSHash.class, Condition.ConditionResult.FAILURE, "FAPI-RW-5.2.2-4");

		callAndContinueOnFailure(ExtractCHash.class, Condition.ConditionResult.FAILURE, "OIDCC-3.3.2.11");

		skipIfMissing(new String[]{"c_hash"}, null, Condition.ConditionResult.INFO,
			ValidateCHash.class, Condition.ConditionResult.FAILURE, "OIDCC-3.3.2.11");

		// call the token endpoint and complete the flow

		createAuthorizationCodeRequest();

		requestAuthorizationCode();

		eventLog.startBlock("Accounts request endpoint TLS test");
		env.mapKey("tls", "accounts_request_endpoint_tls");
		callAndContinueOnFailure(EnsureTLS12.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");
		callAndContinueOnFailure(DisallowTLS10.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");
		callAndContinueOnFailure(DisallowTLS11.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");

		callAndContinueOnFailure(DisallowInsecureCipher.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-1");
		eventLog.endBlock();


		eventLog.startBlock("Accounts resource endpoint TLS test");
		env.mapKey("tls", "accounts_resource_endpoint_tls");
		callAndContinueOnFailure(EnsureTLS12.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");
		callAndContinueOnFailure(DisallowTLS10.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");
		callAndContinueOnFailure(DisallowTLS11.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");

		callAndContinueOnFailure(DisallowInsecureCipher.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-1");
		env.unmapKey("tls");
		eventLog.endBlock();

		requestProtectedResource();

		callAndContinueOnFailure(DisallowAccessTokenInQuery.class, Condition.ConditionResult.FAILURE, "FAPI-R-6.2.1-4");

		callAndStopOnFailure(SetPlainJsonAcceptHeaderForResourceEndpointRequest.class);

		callAndStopOnFailure(CallProtectedResourceWithBearerTokenAndCustomHeaders.class, "RFC7231-5.3.2");

		callAndStopOnFailure(SetPermissiveAcceptHeaderForResourceEndpointRequest.class);

		callAndContinueOnFailure(CallProtectedResourceWithBearerTokenAndCustomHeaders.class, Condition.ConditionResult.FAILURE, "RFC7231-5.3.2");

		callAndStopOnFailure(ClearAcceptHeaderForResourceEndpointRequest.class);

		fireTestFinished();
	}

}
