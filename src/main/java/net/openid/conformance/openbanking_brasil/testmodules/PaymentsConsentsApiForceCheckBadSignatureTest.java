

package net.openid.conformance.openbanking_brasil.testmodules;

	import net.openid.conformance.condition.Condition;
	import net.openid.conformance.condition.client.*;
	import net.openid.conformance.openbanking_brasil.OBBProfile;
	import net.openid.conformance.openbanking_brasil.testmodules.support.*;
	import net.openid.conformance.sequence.ConditionSequence;
	import net.openid.conformance.testmodule.PublishTestModule;

	import java.util.Random;

@PublishTestModule(
	testName = "payments-consents-force-check-signature-test",
	displayName = "Payments Consents API basic test module ",
	summary = "Payments Consents API basic test module",
	profile = OBBProfile.OBB_PROFILE,
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.jwks",
		"mtls.key",
		"mtls.cert",
		"mtls.ca",
		"resource.consentUrl",
		"resource.brazilCpf"
	}
)
public class PaymentsConsentsApiForceCheckBadSignatureTest extends AbstractClientCredentialsGrantFunctionalTestModule {

	@Override
	protected ConditionSequence createGetAccessTokenWithClientCredentialsSequence(Class<? extends ConditionSequence> clientAuthSequence) {
		return new ObtainPaymentsAccessTokenWithClientCredentials(clientAuthSequence);
	}

	@Override
	protected void runTests() {

		int numOfGoodTests = new Random().nextInt(20) + 1;

		eventLog.startBlock("Making a random number of good payment consent requests");
		for(int i = 0; i < numOfGoodTests; i++){
			callAndStopOnFailure(PrepareToPostConsentRequest.class);
			callAndStopOnFailure(FAPIBrazilCreatePaymentConsentRequest.class);
			call(sequence(SignedPaymentConsentSequence.class));

		}

		eventLog.startBlock("Trying a badly signed payment consent request");
		makeBadlySignedPaymentConsentRequest();

	}

	protected void makeBadlySignedPaymentConsentRequest(){
		callAndStopOnFailure(CreateEmptyResourceEndpointRequestHeaders.class);
		callAndStopOnFailure(CreateIdempotencyKey.class);
		callAndStopOnFailure(AddIdempotencyKeyHeader.class);
		callAndStopOnFailure(AddFAPIAuthDateToResourceEndpointRequest.class);
		callAndStopOnFailure(FAPIBrazilExtractClientMTLSCertificateSubject.class);
		call(exec().mapKey("request_object_claims", "consent_endpoint_request"));
		callAndStopOnFailure(AddAudAsPaymentConsentUriToRequestObject.class, "BrazilOB-6.1");
		callAndStopOnFailure(AddIssAsCertificateOuToRequestObject.class, "BrazilOB-6.1");
		callAndStopOnFailure(AddJtiAsUuidToRequestObject.class, "BrazilOB-6.1");
		callAndStopOnFailure(AddIatToRequestObject.class, "BrazilOB-6.1");
		call(exec().unmapKey("request_object_claims"));
		callAndStopOnFailure(FAPIBrazilSignPaymentConsentRequest.class);
		callAndStopOnFailure(InvalidateConsentEndpointRequestSignature.class);
		callAndStopOnFailure(FAPIBrazilCallPaymentConsentEndpointWithBearerToken.class, Condition.ConditionResult.FAILURE);
		callAndContinueOnFailure(EnsureConsentHttpStatusCodeIs400.class, Condition.ConditionResult.FAILURE);
		callAndContinueOnFailure(EnsureContentTypeJson.class, Condition.ConditionResult.FAILURE, "BrazilOB-6.1");
		call(exec().mapKey("server", "org_server"));
		call(exec().mapKey("server_jwks", "org_server_jwks"));
		callAndStopOnFailure(FetchServerKeys.class);
		call(exec().unmapKey("server"));
		call(exec().unmapKey("server_jwks"));
	}
}