package io.fintechlabs.testframework.openbanking;

import io.fintechlabs.testframework.condition.as.AddPrivateKeyJWTToServerConfiguration;
import io.fintechlabs.testframework.condition.as.EnsureClientAssertionTypeIsJwt;
import io.fintechlabs.testframework.condition.as.ExtractClientAssertion;
import io.fintechlabs.testframework.condition.as.ValidateClientAssertionClaims;
import io.fintechlabs.testframework.condition.as.ValidateClientSigningKeySize;
import io.fintechlabs.testframework.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "fapi-rw-id2-ob-client-test-with-private-key-jwt-and-mtls-holder-of-key",
	displayName = "FAPI-RW-ID2-OB: client test (with private_key_jwt and MTLS)",
	summary = "Successful test case scenario where response_type used is code id_token combined with private_key_jwt and MTLS. Requires that the client supports OpenBanking UK specific features like obtaining an intent id prior to authorisation.",
	profile = "FAPI-RW-ID2-OB",
	configurationFields = {
		"server.jwks",
		"client.client_id",
		"client.scope",
		"client.redirect_uri",
		"client.certificate",
		"client.jwks",
	}
)

public class FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKey extends AbstractFAPIRWID2OBClientTest {

	@Override
	protected void addTokenEndpointAuthMethodSupported() {

		callAndStopOnFailure(AddPrivateKeyJWTToServerConfiguration.class);
	}

	@Override
	protected void validateClientAuthentication() {

	callAndStopOnFailure(ExtractClientAssertion.class, "RFC7523-2.2");

	callAndStopOnFailure(EnsureClientAssertionTypeIsJwt.class, "RFC7523-2.2");

	callAndStopOnFailure(ValidateClientAssertionClaims.class, "RFC7523-3");

	callAndStopOnFailure(ValidateClientSigningKeySize.class,"FAPI-R-5.2.2.5");

	}

	@Override
	protected void addCustomValuesToIdToken(){
		//Do nothing
	}

}