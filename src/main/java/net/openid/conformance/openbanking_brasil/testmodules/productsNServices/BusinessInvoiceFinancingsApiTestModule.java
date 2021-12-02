package net.openid.conformance.openbanking_brasil.testmodules.productsNServices;

import net.openid.conformance.condition.Condition;
import net.openid.conformance.openbanking_brasil.OBBProfile;
import net.openid.conformance.openbanking_brasil.productsNServices.invoiceFinancings.BusinessInvoiceFinancingsValidator;
import net.openid.conformance.openbanking_brasil.testmodules.AbstractNoAuthFunctionalTestModule;
import net.openid.conformance.openbanking_brasil.testmodules.support.DoNotStopOnFailure;
import net.openid.conformance.openbanking_brasil.testmodules.support.PrepareToGetProductsNChannelsApi;
import net.openid.conformance.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "ProductsNServices Business Invoice Financings API-test",
	displayName = "Validate structure of ProductsNServices Business Invoice Financings Api resources",
	summary = "Validate structure of ProductsNServices Business Invoice Financings Api resources",
	profile = OBBProfile.OBB_PROFIlE_PHASE1
)
public class BusinessInvoiceFinancingsApiTestModule extends AbstractNoAuthFunctionalTestModule {

	@Override
	protected void runTests() {
		runInBlock("Validate ProductsNServices Business Invoice Financings response", () -> {
			callAndStopOnFailure(PrepareToGetProductsNChannelsApi.class, "business-invoice-financings");
			preCallResource();
			callAndContinueOnFailure(DoNotStopOnFailure.class);
			callAndContinueOnFailure(BusinessInvoiceFinancingsValidator.class,
				Condition.ConditionResult.FAILURE);
		});
	}
}