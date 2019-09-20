package io.fintechlabs.testframework.condition.client;

import com.google.common.base.Strings;
import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import io.fintechlabs.testframework.condition.AbstractCondition;
import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.testmodule.Environment;
import io.fintechlabs.testframework.testmodule.OIDFJSON;

import java.time.Instant;
import java.util.Date;

public class ValidateJARMExpRecommendations extends AbstractCondition {

	// TODO: make this configurable
	private int timeSkewMillis = 5 * 60 * 1000; // 5 minute allowable skew for testing

	@Override
	@PreEnvironment(required = { "jarm_response" } )
	public Environment evaluate(Environment env) {
		Instant now = Instant.now();
		final int allowableLifeTimeMinutes = 10;
		final int minimumLifeTimeSeconds = 60;

		Long exp = env.getLong("jarm_response", "claims.exp");
		if (exp == null) {
			throw error("'exp' claim missing from JARM response");
		}

		// exp recommended to be less than 10 minutes - added after JARM ID1:
		// https://bitbucket.org/openid/fapi/commits/8ac0bc6059cfcfdb6c155efa2d992a1eb86e8b6c -
		if (now.plusMillis(timeSkewMillis).plusSeconds(allowableLifeTimeMinutes*60).isBefore(Instant.ofEpochSecond(exp))) {
			throw error("JARM 'exp' time is further in the future than the recommended "+allowableLifeTimeMinutes+" minutes", args("expiration", new Date(exp * 1000L), "now", now));
		}

		// not mentioned by spec, but for the sake of sanity check the response has a lifetime of at least 60 seconds
		// or it's likely to fall in various real world situations
		// We don't use 'timeSkewMillis' here, as that would allow a zero expiry to pass
		if (now.plusSeconds(minimumLifeTimeSeconds).isAfter(Instant.ofEpochSecond(exp))) {
			throw error("JARM 'exp' time appears to be less than "+minimumLifeTimeSeconds+" seconds", args("expiration", new Date(exp * 1000L), "now", now));
		}

		logSuccess("JARM response 'exp' is less than "+allowableLifeTimeMinutes+" minutes", args("expiration", new Date(exp * 1000L), "now", now));
		return env;

	}

}
