package io.fintechlabs.testframework.fapi;

import io.fintechlabs.testframework.openbanking.FAPIRWID2OBDiscoveryEndpointVerification;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBEnsureRequestObjectInvalidSignatureFailsWithMTLS;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBEnsureRequestObjectInvalidSignatureFailsWithPrivateKeyAndMTLS;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBEnsureServerHandlesNonMatchingIntentId;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBEnsureSignedRequestObjectWithRS256FailsWithMTLS;
import io.fintechlabs.testframework.plan.PublishTestPlan;
import io.fintechlabs.testframework.plan.TestPlan;

@PublishTestPlan (
	testPlanName = "fapi-rw-id2-test-plan",
	displayName = "FAPI-RW-ID2: Authorization server test (latest version)",
	profile = "FAPI-RW-ID2-OpenID-Provider-Authorization-Server-Test",
	testModules = {
		// Normal well behaved client cases
		FAPIRWID2DiscoveryEndpointVerification.class,
		FAPIRWID2.class,
		FAPIRWID2UserRejectsAuthentication.class,
		FAPIRWID2EnsureServerAcceptsRequestObjectWithMultipleAud.class,
		FAPIRWID2EnsureAuthorizationRequestWithoutStateSuccess.class,
		FAPIRWID2OBDiscoveryEndpointVerification.class,

		// Possible failure case
		FAPIRWID2EnsureResponseModeQuery.class,
		FAPIRWID2EnsureDifferentNonceInsideAndOutsideRequestObject.class,
		FAPIRWID2EnsureRegisteredRedirectUri.class,

		// Negative tests for request objects
		FAPIRWID2EnsureRequestObjectWithoutExpFails.class,
		FAPIRWID2EnsureRequestObjectWithoutScopeFails.class,
		FAPIRWID2EnsureRequestObjectWithoutState.class,
		FAPIRWID2EnsureRequestObjectWithoutNonceFails.class,
		FAPIRWID2EnsureRequestObjectWithoutRedirectUriFails.class,
		FAPIRWID2EnsureExpiredRequestObjectFails.class,
		FAPIRWID2EnsureRequestObjectWithBadAudFails.class,
		FAPIRWID2EnsureSignedRequestObjectWithRS256Fails.class,
		FAPIRWID2EnsureRequestObjectSignatureAlgorithmIsNotNone.class,
		FAPIRWID2EnsureRequestObjectInvalidSignatureFails.class,
		FAPIRWID2EnsureMatchingKeyInAuthorizationRequest.class,
		FAPIRWID2OBEnsureSignedRequestObjectWithRS256FailsWithMTLS.class,
		FAPIRWID2OBEnsureRequestObjectInvalidSignatureFailsWithMTLS.class,
		FAPIRWID2OBEnsureRequestObjectInvalidSignatureFailsWithPrivateKeyAndMTLS.class,

		// Negative tests for authorization request
		FAPIRWID2EnsureAuthorizationRequestWithoutRequestObjectFails.class,
		FAPIRWID2EnsureRedirectUriInAuthorizationRequest.class,
		FAPIRWID2EnsureResponseTypeCodeFails.class,

		// Negative tests for token endpoint
		FAPIRWID2EnsureClientIdInTokenEndpointWithMTLS.class,
		FAPIRWID2EnsureMTLSHolderOfKeyRequiredWithMTLS.class,
		FAPIRWID2EnsureAuthorizationCodeIsBoundToClient.class,
		FAPIRWID2EnsureClientIdInTokenEndpointWithPrivateKeyAndMTLSHolderOfKey.class,
		FAPIRWID2EnsureMTLSHolderOfKeyRequiredWithPrivateKeyAndMTLSHolderOfKey.class,

		// Private key specific tests
		FAPIRWID2EnsureSignedClientAssertionWithRS256FailsWithPrivateKeyAndMTLSHolderOfKey.class,
		FAPIRWID2EnsureClientAssertionInTokenEndpointWithPrivateKeyAndMTLSHolderOfKey.class,

		//Refresh token tests
		FAPIRWID2RefreshToken.class,

		// OB systems specific tests
		FAPIRWID2OBEnsureServerHandlesNonMatchingIntentId.class
	},
	variants = {
		FAPIRWID2.variant_mtls,
		FAPIRWID2.variant_privatekeyjwt,
		FAPIRWID2.variant_openbankinguk_mtls,
		FAPIRWID2.variant_openbankinguk_privatekeyjwt
	}
)
public class FAPI_RW_ID2_TestPlan implements TestPlan {

}
