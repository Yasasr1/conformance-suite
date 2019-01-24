package io.fintechlabs.testframework.sequence.client;

import io.fintechlabs.testframework.condition.client.AddNonceToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddStateToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.BuildPlainRedirectToAuthorizationEndpoint;
import io.fintechlabs.testframework.condition.client.CreateAuthorizationEndpointRequestFromClientInformation;
import io.fintechlabs.testframework.condition.client.CreateRandomNonceValue;
import io.fintechlabs.testframework.condition.client.CreateRandomStateValue;
import io.fintechlabs.testframework.condition.client.SetAuthorizationEndpointRequestResponseTypeToCode;
import io.fintechlabs.testframework.sequence.AbstractConditionSequence;

/**
 * @author jricher
 *
 */
public class CreateAuthorizationEndpointRequest extends AbstractConditionSequence {

	/* (non-Javadoc)
	 * @see io.fintechlabs.testframework.sequence.ConditionSequence#evaluate()
	 */
	@Override
	public void evaluate() {

		// Create a valid authorization request
		call(condition(CreateAuthorizationEndpointRequestFromClientInformation.class));

		call(condition(CreateRandomStateValue.class));
		call(exec().exposeEnvironmentString("state"));
		call(condition(AddStateToAuthorizationEndpointRequest.class));

		call(condition(CreateRandomNonceValue.class));
		call(exec().exposeEnvironmentString("nonce"));
		call(condition(AddNonceToAuthorizationEndpointRequest.class));

		runAccessory("response_type",
			condition(SetAuthorizationEndpointRequestResponseTypeToCode.class));

		runAccessory("authorization_request");

		runAccessory("authorization_redirect",
			condition(BuildPlainRedirectToAuthorizationEndpoint.class));

	}

}