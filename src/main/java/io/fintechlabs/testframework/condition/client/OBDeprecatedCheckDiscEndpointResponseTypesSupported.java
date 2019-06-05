package io.fintechlabs.testframework.condition.client;

import java.util.Arrays;

import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.testmodule.Environment;

public class OBDeprecatedCheckDiscEndpointResponseTypesSupported extends ValidateJsonArray {

	private static final String environmentVariable = "response_types_supported";

	private static final String[] SET_VALUES = new String[] { "code", "code id_token", "code token", "code id_token token" };

	private static final String errorMessageNotEnough = "No matching value from server";

	@Override
	@PreEnvironment(required = "server")
	public Environment evaluate(Environment env) {

		return validate(env, environmentVariable, Arrays.asList(SET_VALUES), 1,
				errorMessageNotEnough);

	}



}
