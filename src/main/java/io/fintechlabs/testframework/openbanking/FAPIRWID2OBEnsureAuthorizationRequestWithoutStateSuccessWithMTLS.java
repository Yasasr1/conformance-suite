package io.fintechlabs.testframework.openbanking;

import io.fintechlabs.testframework.fapi.FAPIRWID2;
import io.fintechlabs.testframework.testmodule.PublishTestModule;
import io.fintechlabs.testframework.testmodule.Variant;

@PublishTestModule(
	testName = "fapi-rw-id2-ob-ensure-authorization-request-without-state-success-with-mtls",
	displayName = "FAPI-RW-ID2-OB: ensure authorization endpoint request without state success (with MTLS authentication)",
	summary = "This test makes an authentication request that does not include 'state'. State is an optional parameter, so the authorisation server must successfully authenticate and must not return state nor s_hash.",
	profile = "FAPI-RW-ID2-OB",
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.scope",
		"client.jwks",
		"mtls.key",
		"mtls.cert",
		"mtls.ca",
		"client2.client_id",
		"client2.jwks",
		"resource.resourceUrl",
		"resource.resourceUrlAccountRequests",
		"resource.resourceUrlAccountsResource",
		"resource.institution_id"
	},
	notApplicableForVariants = {
		FAPIRWID2.variant_mtls,
		FAPIRWID2.variant_privatekeyjwt,
		FAPIRWID2.variant_openbankinguk_privatekeyjwt
	}
)
public class FAPIRWID2OBEnsureAuthorizationRequestWithoutStateSuccessWithMTLS extends AbstractFAPIRWID2OBEnsureAuthorizationRequestWithoutStateSuccess {

	@Variant(name = variant_openbankinguk_mtls)
	public void setupOpenBankingUkMTLS() {
		super.setupOpenBankingUkMTLS();
	}
}
