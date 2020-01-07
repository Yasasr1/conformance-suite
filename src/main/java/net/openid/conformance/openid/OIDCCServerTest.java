package net.openid.conformance.openid;

import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.client.ExtractAtHash;
import net.openid.conformance.condition.client.ExtractCHash;
import net.openid.conformance.condition.client.ValidateAtHash;
import net.openid.conformance.condition.client.ValidateCHash;
import net.openid.conformance.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "oidcc-server",
	displayName = "OIDCC",
	summary = "Tests primarily 'happy' flows",
	profile = "OIDCC",
	configurationFields = {
		"server.discoveryUrl",
		"client.scope",
		"client2.scope",
		"resource.resourceUrl"
	}
)
public class OIDCCServerTest extends AbstractOIDCCServerTest {

	@Override
	protected void performAuthorizationEndpointIdTokenValidation() {
		super.performAuthorizationEndpointIdTokenValidation();

		// OP-IDToken-at_hash
		callAndContinueOnFailure(ExtractAtHash.class,
				responseType.includesToken() ? Condition.ConditionResult.FAILURE : Condition.ConditionResult.INFO,
				"OIDCC-3.3.2.11");
		skipIfMissing(new String[] { "at_hash" }, null, Condition.ConditionResult.INFO,
				ValidateAtHash.class, Condition.ConditionResult.FAILURE, "OIDCC-3.3.2.11");

		// OP-IDToken_c_hash
		callAndContinueOnFailure(ExtractCHash.class,
				responseType.includesCode() ? Condition.ConditionResult.FAILURE : Condition.ConditionResult.INFO,
				"OIDCC-3.3.2.11");
		skipIfMissing(new String[] { "c_hash" }, null, Condition.ConditionResult.INFO ,
				ValidateCHash.class, Condition.ConditionResult.FAILURE, "OIDCC-3.3.2.11");
	}
}