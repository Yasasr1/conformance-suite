package io.fintechlabs.testframework.openbanking;

import io.fintechlabs.testframework.plan.PublishTestPlan;
import io.fintechlabs.testframework.plan.TestPlan;

/**
 * @author ddrysdale
 *
 */
@PublishTestPlan (
	testPlanName = "ob-code-with-secret-basic-and-matls-test-plan",
	displayName = "OB: code with secret basic and matls Test Plan",
	profile = "OB",
	testModuleNames = {
		"ob-discovery-end-point-verification",
		"ob-code-with-secret-basic-and-matls",
		"ob-ensure-matls-required-code-with-secret-basic-and-matls",
		"ob-ensure-matching-key-in-authorization-request-code-with-secret-basic-and-matls",
		"ob-ensure-redirect-uri-in-authorization-request-code-with-secret-basic-and-matls",
		"ob-ensure-registered-certificate-for-authorization-code-code-with-secret-basic-and-matls",
		"ob-ensure-registered-redirect-uri-code-with-secret-basic-and-matls",
		"ob-ensure-request-object-signature-algorithm-is-not-none-code-with-secret-basic-and-matls",
		"ob-user-rejects-authentication-code-with-secret-basic-and-matls"
	}

)
public class OBCodeWithSecretBasicAndMATLSTestPlan implements TestPlan {

}
