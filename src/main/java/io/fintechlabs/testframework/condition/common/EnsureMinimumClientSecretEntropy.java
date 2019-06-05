package io.fintechlabs.testframework.condition.common;

import com.google.common.base.Strings;

import io.fintechlabs.testframework.condition.AbstractEnsureMinimumEntropy;
import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.testmodule.Environment;

public class EnsureMinimumClientSecretEntropy extends AbstractEnsureMinimumEntropy {
	/**
	 * The actual amount of required entropy is 128 bits, but we can't accurately measure entropy so a bit of
	 * slop is allowed for.
	 */
	private final double requiredEntropy = 96;

	@Override
	@PreEnvironment(required = "client")
	public Environment evaluate(Environment env) {
		String clientSecret = env.getString("client", "client_secret");

		if (Strings.isNullOrEmpty(clientSecret)) {
			throw error("Can't find client secret");
		}

		return ensureMinimumEntropy(env, clientSecret, requiredEntropy);
	}

}
