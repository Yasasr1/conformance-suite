package net.openid.conformance.openbanking_brasil.testmodules;

import com.google.gson.JsonObject;
import net.openid.conformance.openbanking_brasil.OBBProfile;
import net.openid.conformance.openbanking_brasil.testmodules.support.*;
import net.openid.conformance.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "payments-api-proxy-test-incorrect-cpf",
	displayName = "Payments API test module ensuring unknown CPF is rejected",
	summary = "Payments API test module ensuring unknown CPF is rejected" +
		"Flow:" +
		"Makes a bad DICT payment flow with an unknown CPF value - expects a 422." +
		"Required:" +
		"Consent url pointing at the consent endpoint." +
		"Config: Debtor account must be present in the config. We manually set the local instrument to DICT, add a creditor account, add an unknown cpf value.",
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
public class PaymentsApiIncorrectCPFProxyTestModule extends AbstractOBBrasilFunctionalTestModule {

	@Override
	protected void validateClientConfiguration() {
		callAndStopOnFailure(AddPaymentScope.class);
		super.validateClientConfiguration();
	}

	@Override
	protected void onConfigure(JsonObject config, String baseUrl) {
		callAndStopOnFailure(EnforcePresenceOfDebtorAccount.class);
		callAndContinueOnFailure(SelectDICTCodeLocalInstrument.class);
		callAndContinueOnFailure(RemoveQRCodeFromConfig.class);
		callAndContinueOnFailure(InjectRealCreditorAccountToPaymentConsent.class);
		callAndContinueOnFailure(InjectRealCreditorAccountToPayment.class);
		callAndContinueOnFailure(InjectCorrectButUnknownCpfOnPaymentConsent.class);
		callAndContinueOnFailure(InjectCorrectButUnknownCpfOnPayment.class);
		callAndStopOnFailure(PrepareToPostConsentRequest.class);
		callAndStopOnFailure(SetProtectedResourceUrlToPaymentsEndpoint.class);
	}

	@Override
	protected void validateResponse() {
		callAndStopOnFailure(EnsureResponseCodeWas422.class);
	}

}