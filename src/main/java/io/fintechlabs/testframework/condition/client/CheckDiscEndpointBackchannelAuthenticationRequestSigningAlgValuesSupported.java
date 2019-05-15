package io.fintechlabs.testframework.condition.client;

import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.logging.TestInstanceEventLog;
import io.fintechlabs.testframework.testmodule.Environment;

import java.util.Arrays;

public class CheckDiscEndpointBackchannelAuthenticationRequestSigningAlgValuesSupported extends ValidateJsonArray {

	private static final String environmentVariable = "backchannel_authentication_request_signing_alg_values_supported";

	private static final String[] SET_VALUES = new String[] { "PS256", "ES256" };

	private static final String errorMessageNotEnough = "No matching value from server";


	public CheckDiscEndpointBackchannelAuthenticationRequestSigningAlgValuesSupported(String testId, TestInstanceEventLog log, ConditionResult conditionResultOnFailure, String... requirements) {
		super(testId, log, conditionResultOnFailure, requirements);
	}

	@Override
	@PreEnvironment(required = "server")
	public Environment evaluate(Environment env) {

		return validate(env, environmentVariable, Arrays.asList(SET_VALUES), 1,
			errorMessageNotEnough);

	}
}