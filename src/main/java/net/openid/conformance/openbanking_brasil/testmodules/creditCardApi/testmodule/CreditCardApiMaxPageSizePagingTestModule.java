package net.openid.conformance.openbanking_brasil.testmodules.creditCardApi.testmodule;

import com.google.gson.JsonObject;
import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.client.CallProtectedResourceWithBearerToken;
import net.openid.conformance.openbanking_brasil.*;
import net.openid.conformance.openbanking_brasil.account.*;
import net.openid.conformance.openbanking_brasil.creditCard.*;
import net.openid.conformance.openbanking_brasil.testmodules.AbstractOBBrasilFunctionalTestModule;
import net.openid.conformance.openbanking_brasil.testmodules.support.*;
import net.openid.conformance.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "credit-card-api-max-page-size-paging-test",
	displayName = "Test result set paging: Banks should configure a test credit card transactions list which contains their maximum page-size + 1 items (maximum page-size must be between 25 and 1000). For example, if the bank support a maximum page-size of 50, then they must setup a test resource with at least 51 items. The initial request should receive a response with 50 items. Requesting the 'next' link, found in the metadata, should receive a response with at least 1 item",
	summary = "Test result set paging: Banks should configure a test credit card transactions list that contains their maximum page-size + 1 item (maximum page-size must be between 25 and 1000). For example, if the bank supports a maximum page-size of 50, then they must set up a test resource with at least 51 items. The initial request should receive a response with 50 items. Requesting the 'next' link, found in the metadata, should receive a response with at least 1 item\n" +
		"\u2022 Creates a Consent with the complete set of the credit cards permission group ([\"CREDIT_CARDS_ACCOUNTS_READ\", \"CREDIT_CARDS_ACCOUNTS_BILLS_READ\", \"CREDIT_CARDS_ACCOUNTS_BILLS_TRANSACTIONS_READ\", \"CREDIT_CARDS_ACCOUNTS_LIMITS_READ\", \"CREDIT_CARDS_ACCOUNTS_TRANSACTIONS_READ\", \"RESOURCES_READ\"])\n" +
		"\u2022 Expects a success 201 - Expects a success on Redirect as well \n" +
		"\u2022 Calls GET Accounts API \n" +
		"\u2022 Expects a 200 response \n" +
		"\u2022 Calls GET Accounts API with page size=1000\n" +
		"\u2022 Expects a 200 response and expect that the links and meta attributes display the next page ",
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
public class CreditCardApiMaxPageSizePagingTestModule extends AbstractOBBrasilFunctionalTestModule {

	@Override
	protected void onConfigure(JsonObject config, String baseUrl) {
		callAndStopOnFailure(PrepareAllCreditCardRelatedConsentsForHappyPathTest.class);
		callAndStopOnFailure(AddCreditCardScopes.class);
	}

	@Override
	protected void validateResponse() {

		preCallProtectedResource("Prepare to Fetch Credit Card Transactions");
		callAndStopOnFailure(CardAccountSelector.class);
		callAndStopOnFailure(SetProtectedResourceUrlTransactionsPageSize1000.class);
		callAndStopOnFailure(SetResourceMethodToGet.class);
		callAndStopOnFailure(ClearContentTypeHeaderForResourceEndpointRequest.class);
		callAndStopOnFailure(CallProtectedResourceWithBearerToken.class);
		callAndStopOnFailure(ExtractResponseCodeFromFullResponse.class);
		callAndStopOnFailure(EnsureResponseCodeWas200.class);
		callAndContinueOnFailure(CreditCardAccountsTransactionResponseValidator.class, Condition.ConditionResult.FAILURE);
		callAndContinueOnFailure(EnsureResponseHasLinks.class, Condition.ConditionResult.FAILURE);
		callAndContinueOnFailure(ValidateResponseMetaData.class, Condition.ConditionResult.FAILURE);


		preCallProtectedResource("Prepare to Fetch page 2 of Credit Card Tansactions");
		callAndStopOnFailure(ClearRequestObjectFromEnvironment.class);
		callAndContinueOnFailure(SetProtectedResourceUrlToNextEndpoint.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(SetResourceMethodToGet.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(ClearContentTypeHeaderForResourceEndpointRequest.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(CallProtectedResourceWithBearerToken.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(ExtractResponseCodeFromFullResponse.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(EnsureResponseCodeWas200.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(CreditCardAccountsTransactionResponseValidator.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(EnsureResponseHasLinks.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(ValidateResponseMetaData.class, Condition.ConditionResult.WARNING);

	}

}
