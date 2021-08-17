package net.openid.conformance.sequence.client;

import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.client.AddAudAsPaymentConsentUriToRequestObject;
import net.openid.conformance.condition.client.AddFAPIAuthDateToResourceEndpointRequest;
import net.openid.conformance.condition.client.AddIatToRequestObject;
import net.openid.conformance.condition.client.AddIdempotencyKeyHeader;
import net.openid.conformance.condition.client.AddIssAsCertificateOuToRequestObject;
import net.openid.conformance.condition.client.AddJtiAsUuidToRequestObject;
import net.openid.conformance.condition.client.CallConsentEndpointWithBearerToken;
import net.openid.conformance.condition.client.CallTokenEndpoint;
import net.openid.conformance.condition.client.CheckForAccessTokenValue;
import net.openid.conformance.condition.client.CheckForFAPIInteractionIdInResourceResponse;
import net.openid.conformance.condition.client.CheckIfTokenEndpointResponseError;
import net.openid.conformance.condition.client.CreateEmptyResourceEndpointRequestHeaders;
import net.openid.conformance.condition.client.CreateIdempotencyKey;
import net.openid.conformance.condition.client.CreateTokenEndpointRequestForClientCredentialsGrant;
import net.openid.conformance.condition.client.ExtractAccessTokenFromTokenResponse;
import net.openid.conformance.condition.client.ExtractConsentIdFromConsentEndpointResponse;
import net.openid.conformance.condition.client.ExtractExpiresInFromTokenEndpointResponse;
import net.openid.conformance.condition.client.ExtractSignedJwtFromPaymentConsentResponse;
import net.openid.conformance.condition.client.FAPIBrazilAddConsentIdToClientScope;
import net.openid.conformance.condition.client.FAPIBrazilAddExpirationToConsentRequest;
import net.openid.conformance.condition.client.FAPIBrazilCallPaymentConsentEndpointWithBearerToken;
import net.openid.conformance.condition.client.FAPIBrazilConsentEndpointResponseValidatePermissions;
import net.openid.conformance.condition.client.FAPIBrazilCreateConsentRequest;
import net.openid.conformance.condition.client.FAPIBrazilCreatePaymentConsentRequest;
import net.openid.conformance.condition.client.FAPIBrazilExtractClientMTLSCertificateSubject;
import net.openid.conformance.condition.client.FAPIBrazilSignPaymentConsentRequest;
import net.openid.conformance.condition.client.FAPIBrazilValidateConsentResponseSigningAlg;
import net.openid.conformance.condition.client.FAPIBrazilValidateConsentResponseTyp;
import net.openid.conformance.condition.client.SetConsentsScopeOnTokenEndpointRequest;
import net.openid.conformance.condition.client.SetPaymentsScopeOnTokenEndpointRequest;
import net.openid.conformance.condition.client.ValidateExpiresIn;
import net.openid.conformance.condition.client.ValidatePaymentConsentResponseJwtClaims;
import net.openid.conformance.condition.client.ValidatePaymentConsentSignature;
import net.openid.conformance.sequence.AbstractConditionSequence;
import net.openid.conformance.sequence.ConditionSequence;

public class OpenBankingBrazilPreAuthorizationSteps extends AbstractConditionSequence {

	private boolean secondClient;
	private boolean payments;
	private String currentClient;
	private Class<? extends ConditionSequence> addClientAuthenticationToTokenEndpointRequest;

	public OpenBankingBrazilPreAuthorizationSteps(boolean secondClient, Class<? extends ConditionSequence> addClientAuthenticationToTokenEndpointRequest, boolean payments) {
		this.secondClient = secondClient;
		this.currentClient = secondClient ? "Second client: " : "";
		this.addClientAuthenticationToTokenEndpointRequest = addClientAuthenticationToTokenEndpointRequest;
		this.payments = payments;
	}

		@Override
	public void evaluate() {
		call(exec().startBlock(currentClient + "Use client_credentials grant to obtain Brazil consent"));

		/* create client credentials request */

		callAndStopOnFailure(CreateTokenEndpointRequestForClientCredentialsGrant.class);

		if (payments) {
			callAndStopOnFailure(SetPaymentsScopeOnTokenEndpointRequest.class);
		} else {
			callAndStopOnFailure(SetConsentsScopeOnTokenEndpointRequest.class);
		}

		call(sequence(addClientAuthenticationToTokenEndpointRequest));

		/* get access token */

		callAndStopOnFailure(CallTokenEndpoint.class);

		callAndStopOnFailure(CheckIfTokenEndpointResponseError.class);

		callAndStopOnFailure(CheckForAccessTokenValue.class);

		callAndStopOnFailure(ExtractAccessTokenFromTokenResponse.class);

		callAndContinueOnFailure(ExtractExpiresInFromTokenEndpointResponse.class, "RFC6749-4.4.3", "RFC6749-5.1");

		call(condition(ValidateExpiresIn.class)
				.skipIfObjectMissing("expires_in")
				.onSkip(Condition.ConditionResult.INFO)
				.requirements("RFC6749-5.1")
				.onFail(Condition.ConditionResult.FAILURE)
				.dontStopOnFailure());

		/* create consent request */

		callAndStopOnFailure(CreateEmptyResourceEndpointRequestHeaders.class);

		callAndStopOnFailure(AddFAPIAuthDateToResourceEndpointRequest.class);

		if (payments) {
			// as per https://github.com/OpenBanking-Brasil/areadesenvolvedor/blob/master/documentation/source/swagger/swagger_payments_apis.yaml
			callAndStopOnFailure(CreateIdempotencyKey.class);
			callAndStopOnFailure(AddIdempotencyKeyHeader.class);

			callAndStopOnFailure(FAPIBrazilCreatePaymentConsentRequest.class);

			// to retrieve the organisation id
			callAndStopOnFailure(FAPIBrazilExtractClientMTLSCertificateSubject.class);

			// we reuse the request object conditions to add various jwt claims; it would perhaps make sense to make
			// these more generic.
			call(exec().mapKey("request_object_claims", "consent_endpoint_request"));

			// aud (in the JWT request): the Resource Provider (eg the institution holding the account) must validate if the value of the aud field matches the endpoint being triggered;
			callAndStopOnFailure(AddAudAsPaymentConsentUriToRequestObject.class, "BrazilOB-6.1");

			//iss (in the JWT request and in the JWT response): the receiver of the message shall validate if the value of the iss field matches the organisationId of the sender;
			callAndStopOnFailure(AddIssAsCertificateOuToRequestObject.class, "BrazilOB-6.1");

			//jti (in the JWT request and in the JWT response): the value of the jti field shall be filled with the UUID defined by the institution according to [RFC4122] version 4;
			callAndStopOnFailure(AddJtiAsUuidToRequestObject.class, "BrazilOB-6.1");

			//iat (in the JWT request and in the JWT response): the iat field shall be filled with the message generation time and according to the standard established in [RFC7519](https:// datatracker.ietf.org/doc/html/rfc7519#section-2) to the NumericDate format.
			callAndStopOnFailure(AddIatToRequestObject.class, "BrazilOB-6.1");

			call(exec().unmapKey("request_object_claims"));

			callAndStopOnFailure(FAPIBrazilSignPaymentConsentRequest.class);

			callAndStopOnFailure(FAPIBrazilCallPaymentConsentEndpointWithBearerToken.class);

			callAndStopOnFailure(ExtractSignedJwtFromPaymentConsentResponse.class, "BrazilOB-6.1");

			callAndContinueOnFailure(FAPIBrazilValidateConsentResponseSigningAlg.class, Condition.ConditionResult.FAILURE, "BrazilOB-6.1");

			callAndContinueOnFailure(FAPIBrazilValidateConsentResponseTyp.class, Condition.ConditionResult.FAILURE, "BrazilOB-6.1");

			callAndContinueOnFailure(ValidatePaymentConsentSignature.class, Condition.ConditionResult.FAILURE, "BrazilOB-6.1");

			callAndContinueOnFailure(ValidatePaymentConsentResponseJwtClaims.class, Condition.ConditionResult.FAILURE, "BrazilOB-6.1");
		} else {
			callAndStopOnFailure(FAPIBrazilCreateConsentRequest.class);

			callAndStopOnFailure(FAPIBrazilAddExpirationToConsentRequest.class);

			callAndStopOnFailure(CallConsentEndpointWithBearerToken.class);

			callAndContinueOnFailure(FAPIBrazilConsentEndpointResponseValidatePermissions.class, Condition.ConditionResult.FAILURE);
		}

		callAndStopOnFailure(ExtractConsentIdFromConsentEndpointResponse.class);

		callAndContinueOnFailure(CheckForFAPIInteractionIdInResourceResponse.class, Condition.ConditionResult.FAILURE, "FAPI-R-6.2.1-11", "FAPI1-BASE-6.2.1-11");

		callAndStopOnFailure(FAPIBrazilAddConsentIdToClientScope.class);

		call(exec().endBlock());
	}
}
