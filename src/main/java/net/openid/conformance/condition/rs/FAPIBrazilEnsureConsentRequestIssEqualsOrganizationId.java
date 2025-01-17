package net.openid.conformance.condition.rs;

import com.google.common.base.Strings;
import com.google.gson.JsonObject;
import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.condition.PostEnvironment;
import net.openid.conformance.condition.PreEnvironment;
import net.openid.conformance.condition.client.AbstractFAPIBrazilExtractCertificateSubject;
import net.openid.conformance.testmodule.Environment;

public class FAPIBrazilEnsureConsentRequestIssEqualsOrganizationId extends AbstractCondition {

	@Override
	@PreEnvironment(required = {"client_certificate_subject", "new_consent_request"})
	public Environment evaluate(Environment env) {
		String iss = env.getString("new_consent_request", "claims.iss");
		String organizationId = env.getString("client_certificate_subject", "ou");
		if (Strings.isNullOrEmpty(iss)) {
			throw error("Couldn't find iss in consent request claims");
		}
		if (Strings.isNullOrEmpty(organizationId)) {
			throw error("Couldn't find organizationId, ou, in client certificate subject");
		}
		if(iss.equals(organizationId)) {
			logSuccess("iss claim in consent request matches organizationId in client certificate", args("iss", iss));
		} else {
			throw error("iss claim in consent request does not match organizationId in client certificate",
				args("iss", iss, "client_certificate_subject", env.getObject("client_certificate_subject")));
		}



		return env;
	}

}
