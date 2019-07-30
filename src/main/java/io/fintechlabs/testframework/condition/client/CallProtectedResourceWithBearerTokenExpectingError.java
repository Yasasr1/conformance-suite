package io.fintechlabs.testframework.condition.client;

import org.springframework.web.client.RestClientResponseException;

import com.google.common.base.Strings;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import io.fintechlabs.testframework.condition.PostEnvironment;
import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.testmodule.Environment;
import io.fintechlabs.testframework.testmodule.OIDFJSON;

public class CallProtectedResourceWithBearerTokenExpectingError extends AbstractCallProtectedResourceWithBearerToken {

	@Override
	@PreEnvironment(required = { "access_token", "resource" }, strings = "protected_resource_url")
	@PostEnvironment(required = "resource_endpoint_response_headers", strings = "resource_endpoint_response")
	public Environment evaluate(Environment env) {

		return callProtectedResource(env);
	}

	@Override
	protected Environment handleClientResponse(Environment env, JsonObject responseCode, String responseBody, JsonObject responseHeaders) {

		// RFC6750 §3.1 (referenced by FAPI-R §6.2.1 etc) only states that the resource server SHOULD respond with HTTP 4xx codes.
		// We allow a JSON error response, but warn about the status code.

		if (Strings.isNullOrEmpty(responseBody)) {
			throw error("Empty success response from the resource endpoint");
		} else {
			try {
				JsonElement jsonRoot = new JsonParser().parse(responseBody);
				if (jsonRoot == null || !jsonRoot.isJsonObject()) {
					throw error("Resource endpoint indicated success and did not return a JSON object");
				}

				JsonObject responseObj = jsonRoot.getAsJsonObject();

				if (responseObj.has("error") && !Strings.isNullOrEmpty(OIDFJSON.getString(responseObj.get("error")))) {
					log(args("msg", "Resource endpoint returned a JSON error, but HTTP status indicated success",
							"result", ConditionResult.WARNING,
							"code", responseCode.get("code"),
							"error", responseObj.get("error"),
							"body", responseBody));
					return env;
				} else {
					throw error("No error from resource endpoint", responseObj);
				}

			} catch (JsonParseException e) {
				throw error(e);
			}
		}
	}

	@Override
	protected Environment handleClientResponseException(Environment env, RestClientResponseException e) {

		logSuccess("Resource endpoint returned error", args("code", e.getRawStatusCode(), "status", e.getStatusText(), "body", e.getResponseBodyAsString()));

		return env;
	}
}
