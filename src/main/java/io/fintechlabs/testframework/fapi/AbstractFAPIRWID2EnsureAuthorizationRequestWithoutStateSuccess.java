package io.fintechlabs.testframework.fapi;

import io.fintechlabs.testframework.condition.client.AddExpToRequestObject;
import io.fintechlabs.testframework.condition.client.BuildRequestObjectRedirectToAuthorizationEndpoint;
import io.fintechlabs.testframework.condition.client.CheckIfAuthorizationEndpointError;
import io.fintechlabs.testframework.condition.client.CheckMatchingCallbackParameters;
import io.fintechlabs.testframework.condition.client.CheckMatchingStateParameter;
import io.fintechlabs.testframework.condition.client.ConvertAuthorizationEndpointRequestToRequestObject;
import io.fintechlabs.testframework.condition.client.ExtractAuthorizationCodeFromAuthorizationResponse;
import io.fintechlabs.testframework.condition.client.SignRequestObject;

public abstract class AbstractFAPIRWID2EnsureAuthorizationRequestWithoutStateSuccess extends AbstractFAPIRWID2EnsureRequestObjectWithoutState {

	protected AbstractFAPIRWID2EnsureAuthorizationRequestWithoutStateSuccess(StepsConfiguration stepsConfiguration) {
		super(stepsConfiguration);
	}

	@Override
	protected void performAuthorizationFlow() {
		eventLog.startBlock(currentClientString() + "Make request to authorization endpoint");

		createAuthorizationRequest();

		createAuthorizationRedirect();

		performRedirect();
	}

	@Override
	protected void createAuthorizationRedirect() {
		callAndStopOnFailure(ConvertAuthorizationEndpointRequestToRequestObject.class);

		callAndStopOnFailure(AddExpToRequestObject.class);

		callAndStopOnFailure(SignRequestObject.class);

		callAndStopOnFailure(BuildRequestObjectRedirectToAuthorizationEndpoint.class);
	}

	@Override
	protected void onAuthorizationCallbackResponse() {
		callAndStopOnFailure(CheckMatchingCallbackParameters.class);

		callAndStopOnFailure(CheckIfAuthorizationEndpointError.class);

		callAndStopOnFailure(CheckMatchingStateParameter.class);

		callAndStopOnFailure(ExtractAuthorizationCodeFromAuthorizationResponse.class);

		performPostAuthorizationFlow();
	}

}
