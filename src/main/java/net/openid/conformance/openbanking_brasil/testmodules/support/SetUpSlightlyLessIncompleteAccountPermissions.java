package net.openid.conformance.openbanking_brasil.testmodules.support;

import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.PostEnvironment;
import net.openid.conformance.testmodule.Environment;

public class SetUpSlightlyLessIncompleteAccountPermissions extends AbstractCondition {

	@Override
	@PostEnvironment(strings = "consent_permissions")
	public Environment evaluate(Environment env) {
		String[] permissions = {"ACCOUNTS_READ", "RESOURCES_READ"};
		env.putString("consent_permissions", String.join(" ", permissions));
		logSuccess("Set incomplete accounts permissions", args("permissions", permissions));
		return env;
	}
}