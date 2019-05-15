package io.fintechlabs.testframework.condition.as;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.fintechlabs.testframework.condition.AbstractCondition;
import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.logging.TestInstanceEventLog;
import io.fintechlabs.testframework.testmodule.Environment;

public class CheckNotificationCallbackOnlyAuthReqId extends AbstractCondition {

	private final String keyExpected = "auth_req_id";

	public CheckNotificationCallbackOnlyAuthReqId(String testId, TestInstanceEventLog log, ConditionResult conditionResultOnFailure, String... requirements) {
		super(testId, log, conditionResultOnFailure, requirements);
	}

	@Override
	@PreEnvironment( required = { "notification_callback" })
	public Environment evaluate(Environment env) {
		JsonElement bodyCallback = env.getElementFromObject("notification_callback", "body_json");

		if (bodyCallback == null || !bodyCallback.isJsonObject()) {
			throw error("body received in notification callback must be JSON");
		}

		JsonObject bodyJson = bodyCallback.getAsJsonObject();

		int keySize = bodyJson.size();

		if (keySize == 0) {
			throw error("body received in notification callback was empty");
		} else if (keySize > 1 || !bodyJson.keySet().contains(keyExpected)) {
			throw error("body received in notification callback did not contain only auth_req_id", args("actual", bodyJson));
		}

		logSuccess("body received in notification callback contained only auth_req_id", args("body", bodyCallback));

		return env;
	}
}