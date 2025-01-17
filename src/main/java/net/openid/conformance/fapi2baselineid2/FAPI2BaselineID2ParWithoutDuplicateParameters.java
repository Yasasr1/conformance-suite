package net.openid.conformance.fapi2baselineid2;

import net.openid.conformance.condition.client.BuildRequestObjectByReferenceRedirectToAuthorizationEndpointWithoutDuplicates;
import net.openid.conformance.testmodule.PublishTestModule;
import net.openid.conformance.variant.VariantNotApplicable;

@PublishTestModule(
	testName = "fapi2-baseline-id2-par-without-duplicate-parameters",
	displayName = "FAPI2-Baseline-ID2: PAR request without duplicate parameters",
	summary = "This test makes a PAR request and calls the authorization endpoint passing only the client_id and request_uri parameters - which must succeed, as per section 5 of https://datatracker.ietf.org/doc/html/rfc9101 - this intent was confirmed by the FAPI working group in https://bitbucket.org/openid/fapi/issues/315/par-certification-question-must-servers",
	profile = "FAPI2-Baseline-ID2",
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.scope",
		"client.jwks",
		"mtls.key",
		"mtls.cert",
		"mtls.ca",
		"client2.client_id",
		"client2.scope",
		"client2.jwks",
		"mtls2.key",
		"mtls2.cert",
		"mtls2.ca",
		"resource.resourceUrl"
	}
)
public class FAPI2BaselineID2ParWithoutDuplicateParameters extends AbstractFAPI2BaselineID2ServerTestModule {

	@Override
	protected void performPARRedirectWithRequestUri() {
		callAndStopOnFailure(BuildRequestObjectByReferenceRedirectToAuthorizationEndpointWithoutDuplicates.class, "PAR-4");
		performRedirect();
	}
}
