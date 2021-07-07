package net.openid.conformance.openbanking_brasil.creditOperations.advances;

import com.google.gson.JsonObject;
import net.openid.conformance.condition.PreEnvironment;
import net.openid.conformance.condition.client.AbstractJsonAssertingCondition;
import net.openid.conformance.logging.ApiName;
import net.openid.conformance.testmodule.Environment;

/**
 * This is validator for API - Adiantamento a Depositantes - Contrato | Contract
 * See https://openbanking-brasil.github.io/areadesenvolvedor/#adiantamento-a-depositantes-contrato
 */

@ApiName("Advances Contract")
public class AdvancesContractResponseValidator extends AbstractJsonAssertingCondition {

	@Override
	@PreEnvironment(strings = "resource_endpoint_response")
	public Environment evaluate(Environment environment) {
		JsonObject body = bodyFrom(environment);

		assertHasField(body, "$.data");
		assertHasStringField(body, "$.data.contractNumber");
		assertHasStringField(body, "$.data.ipocCode");
		assertHasStringField(body, "$.data.productName");
		assertHasStringField(body, "$.data.productType");
		assertHasStringField(body, "$.data.productSubType");
		assertHasStringField(body, "$.data.contractDate");
		assertHasStringField(body, "$.data.settlementDate");
		assertHasDoubleField(body, "$.data.contractAmount");
		assertHasStringField(body, "$.data.currency");
		assertHasStringField(body, "$.data.dueDate");
		assertHasStringField(body, "$.data.instalmentPeriodicity");
		assertHasStringField(body, "$.data.instalmentPeriodicityAdditionalInfo");
		assertHasStringField(body, "$.data.firstInstalmentDueDate");
		assertHasDoubleField(body, "$.data.CET");
		assertHasStringField(body, "$.data.amortizationScheduled");
		assertHasStringField(body, "$.data.amortizationScheduledAdditionalInfo");

		assertHasField(body, "$.data.interestRates");

		assertHasStringField(body, "$.data.interestRates[0].taxType");
		assertHasStringField(body, "$.data.interestRates[0].interestRateType");
		assertHasStringField(body, "$.data.interestRates[0].taxPeriodicity");
		assertHasStringField(body, "$.data.interestRates[0].calculation");
		assertHasStringField(body, "$.data.interestRates[0].referentialRateIndexerType");
		assertHasDoubleField(body, "$.data.interestRates[0].preFixedRate");
		assertHasDoubleField(body, "$.data.interestRates[0].postFixedRate");
		assertHasStringField(body, "$.data.interestRates[0].additionalInfo");

		assertHasField(body, "$.data.contractedFees");

		assertHasStringField(body, "$.data.contractedFees[0].feeName");
		assertHasStringField(body, "$.data.contractedFees[0].feeCode");
		assertHasStringField(body, "$.data.contractedFees[0].feeChargeType");
		assertHasStringField(body, "$.data.contractedFees[0].feeCharge");
		assertHasIntField(body, "$.data.contractedFees[0].feeAmount");
		assertHasIntField(body, "$.data.contractedFees[0].feeRate");

		assertHasField(body, "$.data.contractedFinanceCharges");

		assertHasStringField(body, "$.data.contractedFinanceCharges[0].chargeType");
		assertHasStringField(body, "$.data.contractedFinanceCharges[0].chargeAdditionalInfo");

		return environment;
	}
}