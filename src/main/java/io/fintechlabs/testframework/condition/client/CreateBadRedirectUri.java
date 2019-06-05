package io.fintechlabs.testframework.condition.client;

import org.apache.commons.lang3.RandomStringUtils;

import com.google.common.base.Strings;

import io.fintechlabs.testframework.condition.AbstractCondition;
import io.fintechlabs.testframework.condition.PostEnvironment;
import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.testmodule.Environment;

public class CreateBadRedirectUri extends AbstractCondition {

	@Override
	@PreEnvironment(strings = "base_url")
	@PostEnvironment(strings = "redirect_uri")
	public Environment evaluate(Environment in) {
		String baseUrl = in.getString("base_url");

		if (Strings.isNullOrEmpty(baseUrl)) {
			throw error("Base URL was null or empty");
		}

		// create a random redirect URI which shouldn't be registered with the server
		String redirectUri = baseUrl + "/" + RandomStringUtils.randomAlphanumeric(10);
		in.putString("redirect_uri", redirectUri);

		logSuccess("Created redirect URI",
			args("redirect_uri", redirectUri));

		return in;
	}

}
