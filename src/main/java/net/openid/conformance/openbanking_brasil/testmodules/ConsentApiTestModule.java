package net.openid.conformance.openbanking_brasil.testmodules;

import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.client.FAPIBrazilAddExpirationToConsentRequest;
import net.openid.conformance.openbanking_brasil.*;
import net.openid.conformance.openbanking_brasil.consent.ConsentDetailsIdentifiedByConsentIdValidator;
import net.openid.conformance.openbanking_brasil.consent.CreateNewConsentValidator;
import net.openid.conformance.openbanking_brasil.testmodules.support.*;
import net.openid.conformance.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "consent-api-test",
	displayName = "Validate structure of all consent API resources",
	summary = "Validates the structure of all consent API resources",
	profile = OBBProfile.OBB_PROFILE,
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.scope",
		"client.jwks",
		"mtls.key",
		"mtls.cert",
		"mtls.ca",
		"resource.consentUrl",
		"resource.brazilCpf"
	}
)
public class ConsentApiTestModule extends AbstractClientCredentialsGrantFunctionalTestModule {

	@Override
	protected void runTests() {

		runInBlock("Validating create consent response", () -> {
			callAndStopOnFailure(PrepareToPostConsentRequest.class);
			callAndStopOnFailure(FAPIBrazilAddExpirationToConsentRequest.class);
			callAndContinueOnFailure(CallConsentApiWithBearerToken.class, Condition.ConditionResult.FAILURE);
			callAndContinueOnFailure(CreateNewConsentValidator.class, Condition.ConditionResult.FAILURE);
		});


		runInBlock("Validating get consent response", () -> {
			callAndStopOnFailure(ConsentIdExtractor.class);
			callAndStopOnFailure(PrepareToFetchConsentRequest.class);
			callAndContinueOnFailure(CallConsentApiWithBearerToken.class, Condition.ConditionResult.FAILURE);
			callAndContinueOnFailure(ConsentDetailsIdentifiedByConsentIdValidator.class, Condition.ConditionResult.FAILURE);
		});

		runInBlock("Deleting consent", () -> {
			callAndContinueOnFailure(PrepareToDeleteConsent.class, Condition.ConditionResult.FAILURE);
			callAndContinueOnFailure(CallConsentApiWithBearerToken.class, Condition.ConditionResult.FAILURE);
			callAndStopOnFailure(PrepareToFetchConsentRequest.class);
			callAndStopOnFailure(IgnoreResponseError.class);
			callAndContinueOnFailure(CallConsentApiWithBearerToken.class, Condition.ConditionResult.FAILURE);
			callAndContinueOnFailure(ValidateConsentWasNotFound.class);
		});

	}


}