package io.fintechlabs.testframework.condition.client;

import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.logging.TestInstanceEventLog;
import io.fintechlabs.testframework.testmodule.Environment;

import java.util.Arrays;

public class CheckBackchannelTokenDeliveryPollModeSupported extends ValidateJsonArray {

	private final String environmentVariable = "backchannel_token_delivery_modes_supported";

	private final String pollMode = "poll";

	private final String errorMessageNotEnough = "No matching value from server";

	public CheckBackchannelTokenDeliveryPollModeSupported(String testId, TestInstanceEventLog log, ConditionResult conditionResultOnFailure, String... requirements) {
		super(testId, log, conditionResultOnFailure, requirements);
	}

	@Override
	@PreEnvironment(required = "server")
	public Environment evaluate(Environment env) {

		return validate(env, environmentVariable, Arrays.asList(pollMode), 1, errorMessageNotEnough);

	}
}