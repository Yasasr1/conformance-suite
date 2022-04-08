package net.openid.conformance.fapi2baselineid2;

import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.client.CheckDiscEndpointClaimsParameterSupported;
import net.openid.conformance.condition.client.CheckForUnexpectedClaimsInIdToken;
import net.openid.conformance.condition.client.EnsureIdTokenContainsRequestedClaims;
import net.openid.conformance.condition.client.IdmvpAddClaimsToAuthorizationEndpointRequestIdTokenClaims;
import net.openid.conformance.condition.client.IdmvpCheckClaimsSupported;
import net.openid.conformance.sequence.ConditionSequence;
import net.openid.conformance.testmodule.PublishTestModule;
import net.openid.conformance.variant.FAPI2ID2OPProfile;
import net.openid.conformance.variant.VariantNotApplicable;

@PublishTestModule(
	testName = "fapi2-baseline-id2-idmvp-test-claims-parameter-idtoken-identity-claims",
	displayName = "FAPI2-Baseline-ID2: test requesting id_token identity claims using the claims parameter",
	summary = "The test will request the 6 IDMVP identity are returned in the id_token (using a variety of different forms of request), and will fail if any are not returned.\n\nThe test must be performed using a user which has all six supported claims present on the server.",
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
@VariantNotApplicable(parameter = FAPI2ID2OPProfile.class, values = { "plain_fapi", "openbanking_uk", "consumerdataright_au", "openbanking_brazil" })
public class FAPI2BaselineID2IdmvpTestClaimsParameterIdTokenIdentityClaims extends AbstractFAPI2BaselineID2ServerTestModule {

	@Override
	protected ConditionSequence makeCreateAuthorizationRequestSteps() {
		callAndContinueOnFailure(CheckDiscEndpointClaimsParameterSupported.class, Condition.ConditionResult.FAILURE, "OIDCD-3");

		callAndContinueOnFailure(IdmvpCheckClaimsSupported.class, Condition.ConditionResult.FAILURE, "OIDCD-3", "IDMVP");

		return super.makeCreateAuthorizationRequestSteps()
			.then(condition(IdmvpAddClaimsToAuthorizationEndpointRequestIdTokenClaims.class).requirements("OIDCC-5.1", "OIDCC-5.5", "IDMVP"));
	}

	@Override
	protected void exchangeAuthorizationCode() {
		super.exchangeAuthorizationCode();

		callAndContinueOnFailure(EnsureIdTokenContainsRequestedClaims.class, Condition.ConditionResult.FAILURE, "OIDCC-5.5");

		// We don't include this check in the more general PerformStandardIdTokenChecks as it could be pretty noisy
		callAndContinueOnFailure(CheckForUnexpectedClaimsInIdToken.class, Condition.ConditionResult.WARNING, "OIDCC-5.1");
	}

	@Override
	protected void requestProtectedResource() {
		// not strictly necessary in this test, but also does no harm, with the advantage that it means
		// we can run this test against the rp tests (which require a userinfo call as the final step)
		super.requestProtectedResource();
	}
}
