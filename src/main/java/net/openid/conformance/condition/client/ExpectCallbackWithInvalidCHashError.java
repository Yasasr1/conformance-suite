package net.openid.conformance.condition.client;

import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.testmodule.Environment;

public class ExpectCallbackWithInvalidCHashError extends AbstractCondition {

	@Override
	public Environment evaluate(Environment env) {
		createBrowserInteractionPlaceholder("The client must show an error message that the c_hash value in the id_token from the authorization_endpoint does not match the c_hash value in the request object - upload a log file or screenshot of the error.", true);
		return env;
	}

}
