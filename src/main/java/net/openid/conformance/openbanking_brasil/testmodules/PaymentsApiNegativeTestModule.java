package net.openid.conformance.openbanking_brasil.testmodules;

import com.google.gson.JsonObject;
import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.client.*;
import net.openid.conformance.fapi1advancedfinal.SetApplicationJwtAcceptHeaderForResourceEndpointRequest;
import net.openid.conformance.fapi1advancedfinal.SetApplicationJwtContentTypeHeaderForResourceEndpointRequest;
import net.openid.conformance.openbanking_brasil.OBBProfile;
import net.openid.conformance.openbanking_brasil.testmodules.support.*;
import net.openid.conformance.testmodule.PublishTestModule;
import net.openid.conformance.variant.FAPI1FinalOPProfile;

@PublishTestModule(
	testName = "payments-api-negative-tests",
	displayName = "Payments API basic negative test modules",
	summary = "Payments API basic negative test modules",
	profile = OBBProfile.OBB_PROFILE,
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.jwks",
		"mtls.key",
		"mtls.cert",
		"mtls.ca",
		"resource.consentUrl",
		"resource.brazilCpf",
		"resource.resourceUrl"
	}
)
public class PaymentsApiNegativeTestModule extends AbstractOBBrasilFunctionalTestModule {

	@Override
	protected void validateClientConfiguration() {
		callAndStopOnFailure(AddPaymentScope.class);
		super.validateClientConfiguration();
	}

	@Override
	protected void onConfigure(JsonObject config, String baseUrl) {
		eventLog.startBlock("Validating consent and payment request are the same");
		callAndStopOnFailure(ValidatePaymentAndConsentHaveSameProperties.class);

		eventLog.startBlock("Preparing consent request, setting payment request to incorrect currency type");
		callAndStopOnFailure(PrepareToPostConsentRequest.class);
		callAndStopOnFailure(SetProtectedResourceUrlToPaymentsEndpoint.class);
		callAndStopOnFailure(SetIncorrectCurrencyPayment.class);
	}

	@Override
	protected void validateResponse() {
		eventLog.startBlock("Beginning error validation");
		callAndContinueOnFailure(EnsureResponseCodeWas422.class, Condition.ConditionResult.FAILURE);
		callAndContinueOnFailure(EnsureResourceResponseReturnedJwtContentType.class, Condition.ConditionResult.FAILURE);
		callAndContinueOnFailure(EnsurePaymentCodeIsCorrect.class, Condition.ConditionResult.FAILURE);
	}

	@Override
	protected void requestProtectedResource() {

		// verify the access token against a protected resource
		eventLog.startBlock("Making request to payments with a currency differing to the consent requested - expecting failure");
		makeRequest(true);
		eventLog.endBlock();
		validateResponse();

		eventLog.startBlock("Resetting payment request");
		callAndStopOnFailure(ResetPaymentRequest.class);
		eventLog.endBlock();

		eventLog.startBlock("Making a new consent, setting the amount on payment request to differ from our consent request");
		makeConsent();
		callAndStopOnFailure(SetIncorrectAmountInPayment.class);
		eventLog.endBlock();

		eventLog.startBlock("Making request to payments with an amount differing to the consent requested - expecting failure");
		makeRequest(true);
		eventLog.endBlock();
		validateResponse();

		eventLog.startBlock("Resetting payment request");
		callAndStopOnFailure(ResetPaymentRequest.class);
		eventLog.endBlock();

		eventLog.startBlock("Running a good consent and payment request api - expected to pass");
		makeRequest(false);
		callAndContinueOnFailure(EnsureResourceResponseReturnedJwtContentType.class, Condition.ConditionResult.FAILURE);
		eventLog.endBlock();

		eventLog.startBlock("Setting currency of payment to be different to the consent request");
		makeConsent();
		eventLog.endBlock();
	}

	protected void makeConsent(){
		callAndStopOnFailure(PrepareToPostConsentRequest.class);
		callAndStopOnFailure(FAPIBrazilCreatePaymentConsentRequest.class);
		call(sequence(SignedPaymentConsentSequence.class));
	}

	protected void makeRequest(boolean fail){

		callAndStopOnFailure(CreateEmptyResourceEndpointRequestHeaders.class);

		if (isSecondClient()) {
			if (getVariant(FAPI1FinalOPProfile.class) == FAPI1FinalOPProfile.CONSUMERDATARIGHT_AU) {
				// CDR requires this header for all authenticated resource server endpoints
				callAndStopOnFailure(AddFAPIAuthDateToResourceEndpointRequest.class, "FAPI1-BASE-6.2.2-3", "CDR-http-headers");
			}
		} else {
			// these are optional; only add them for the first client
			callAndStopOnFailure(AddFAPIAuthDateToResourceEndpointRequest.class, "FAPI1-BASE-6.2.2-3");
			callAndStopOnFailure(AddIpV4FapiCustomerIpAddressToResourceEndpointRequest.class, "FAPI1-BASE-6.2.2-4");
			if (getVariant(FAPI1FinalOPProfile.class) == FAPI1FinalOPProfile.CONSUMERDATARIGHT_AU) {
				// CDR requires this header when the x-fapi-customer-ip-address header is present
				callAndStopOnFailure(AddCdrXCdsClientHeadersToResourceEndpointRequest.class, "CDR-http-headers");
			}

			callAndStopOnFailure(CreateRandomFAPIInteractionId.class);
			callAndStopOnFailure(AddFAPIInteractionIdToResourceEndpointRequest.class, "FAPI1-BASE-6.2.2-5");
		}

		if (getVariant(FAPI1FinalOPProfile.class) == FAPI1FinalOPProfile.CONSUMERDATARIGHT_AU) {
			callAndStopOnFailure(AddCdrXvToResourceEndpointRequest.class, "CDR-http-headers");
		}

		if (getVariant(FAPI1FinalOPProfile.class) == FAPI1FinalOPProfile.OPENBANKING_BRAZIL) {
			if (brazilPayments) {
				// setup to call the payments initiation API, which requires a signed jwt request body
				call(sequenceOf(condition(CreateIdempotencyKey.class), condition(AddIdempotencyKeyHeader.class)));
				callAndStopOnFailure(SetApplicationJwtContentTypeHeaderForResourceEndpointRequest.class);
				callAndStopOnFailure(SetApplicationJwtAcceptHeaderForResourceEndpointRequest.class);
				callAndStopOnFailure(SetResourceMethodToPost.class);
				callAndStopOnFailure(CreatePaymentRequestEntityClaims.class);

				// we reuse the request object conditions to add various jwt claims; it would perhaps make sense to make
				// these more generic.
				call(exec().mapKey("request_object_claims", "resource_request_entity_claims"));

				// aud (in the JWT request): the Resource Provider (eg the institution holding the account) must validate if the value of the aud field matches the endpoint being triggered;
				callAndStopOnFailure(AddAudAsPaymentInitiationUriToRequestObject.class, "BrazilOB-6.1");

				//iss (in the JWT request and in the JWT response): the receiver of the message shall validate if the value of the iss field matches the organisationId of the sender;
				callAndStopOnFailure(AddIssAsCertificateOuToRequestObject.class, "BrazilOB-6.1");

				//jti (in the JWT request and in the JWT response): the value of the jti field shall be filled with the UUID defined by the institution according to [RFC4122] version 4;
				callAndStopOnFailure(AddJtiAsUuidToRequestObject.class, "BrazilOB-6.1");

				//iat (in the JWT request and in the JWT response): the iat field shall be filled with the message generation time and according to the standard established in [RFC7519](https:// datatracker.ietf.org/doc/html/rfc7519#section-2) to the NumericDate format.
				callAndStopOnFailure(AddIatToRequestObject.class, "BrazilOB-6.1");

				call(exec().unmapKey("request_object_claims"));

				callAndStopOnFailure(FAPIBrazilSignPaymentInitiationRequest.class);
			}
		}

		if(fail) {
			callAndStopOnFailure(CallProtectedResourceAndExpectFailure.class);
		} else {
			callAndStopOnFailure(CallProtectedResourceWithBearerTokenAndCustomHeaders.class);
		}
	}

}