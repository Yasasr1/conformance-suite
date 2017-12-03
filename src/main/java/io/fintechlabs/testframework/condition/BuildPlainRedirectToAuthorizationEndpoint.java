/*******************************************************************************
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

package io.fintechlabs.testframework.condition;

import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.base.Strings;
import com.google.gson.JsonObject;

import io.fintechlabs.testframework.logging.EventLog;
import io.fintechlabs.testframework.testmodule.Environment;

/**
 * @author jricher
 *
 */
public class BuildPlainRedirectToAuthorizationEndpoint extends AbstractCondition {

	/**
	 * @param testId
	 * @param log
	 */
	public BuildPlainRedirectToAuthorizationEndpoint(String testId, EventLog log, boolean optional) {
		super(testId, log, optional);
		// TODO Auto-generated constructor stub
	}

	/* (non-Javadoc)
	 * @see io.fintechlabs.testframework.testmodule.Condition#evaluate(io.fintechlabs.testframework.testmodule.Environment)
	 */
	@Override
	@PreEnvironment(required = {"authorization_endpoint_request", "server"})
	@PostEnvironment(strings = "redirect_to_authorization_endpoint")
	public Environment evaluate(Environment env) {
		
		if (!env.containsObj("authorization_endpoint_request")) {
			return error("Couldn't find authorization endpoint request");
		}
		
		JsonObject authorizationEndpointRequest = env.get("authorization_endpoint_request");
		
		String authorizationEndpoint = env.getString("server", "authorization_endpoint");
		
		if (Strings.isNullOrEmpty(authorizationEndpoint)) {
			return error("Couldn't find authorization endpoint");
		}
		
		
		// send a front channel request to start things off
		UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(authorizationEndpoint);
		
		for (String key : authorizationEndpointRequest.keySet()) {
			// assume everything is a string for now
			builder.queryParam(key, authorizationEndpointRequest.get(key).getAsString());
		}
		
		String redirectTo = builder.toUriString();

		logSuccess("Sending to authorization endpoint", args("redirect_to_authorization_endpoint", redirectTo));
		
		env.putString("redirect_to_authorization_endpoint", redirectTo);
		
		return env;
	}

}
