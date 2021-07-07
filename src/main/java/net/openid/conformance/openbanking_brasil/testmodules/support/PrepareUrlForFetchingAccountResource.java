package net.openid.conformance.openbanking_brasil.testmodules.support;

import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.condition.PostEnvironment;
import net.openid.conformance.condition.PreEnvironment;
import net.openid.conformance.testmodule.Environment;

public class PrepareUrlForFetchingAccountResource extends AbstractCondition {

	@Override
	@PreEnvironment(strings = "accountId")
	@PostEnvironment(strings = "base_resource_url")
	public Environment evaluate(Environment env) {
		String resourceUrl = env.getString("protected_resource_url");
		env.putString("base_resource_url", resourceUrl);
		String accountId = env.getString("accountId");
		resourceUrl = resourceUrl.concat("/").concat(accountId);
		env.putString("protected_resource_url", resourceUrl);
		return env;
	}
}