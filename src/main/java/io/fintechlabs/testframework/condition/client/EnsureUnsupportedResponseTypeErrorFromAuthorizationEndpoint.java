package io.fintechlabs.testframework.condition.client;

import com.google.common.base.Strings;
import io.fintechlabs.testframework.condition.AbstractCondition;
import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.logging.TestInstanceEventLog;
import io.fintechlabs.testframework.testmodule.Environment;

/**
 * Check to make sure a "unsupported_response_type" error was received from the server
 */
public class EnsureUnsupportedResponseTypeErrorFromAuthorizationEndpoint extends AbstractCondition {

	public EnsureUnsupportedResponseTypeErrorFromAuthorizationEndpoint(String testId, TestInstanceEventLog log, ConditionResult conditionResultOnFailure, String... requirements) {
		super(testId, log, conditionResultOnFailure, requirements);
	}

	@Override
	@PreEnvironment(required = "authorization_endpoint_response")
	public Environment evaluate(Environment in) {

		if (!Strings.isNullOrEmpty(in.getString("authorization_endpoint_response", "error"))) {
			if (in.getString("authorization_endpoint_response","error").equals("unsupported_response_type")){
				logSuccess("unsupported_response_type error from the authorization endpoint");
				return in;
			} else {
				throw error("Incorrect error from the authorization endpoint", in.getObject("authorization_endpoint_response"));
			}
		} else {
			throw error("No unsupported_response_type error found from the authorization endpoint", in.getObject("authorization_endpoint_response"));
		}

	}

}
