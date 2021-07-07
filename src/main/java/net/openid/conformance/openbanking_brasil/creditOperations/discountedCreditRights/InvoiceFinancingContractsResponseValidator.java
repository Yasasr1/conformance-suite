package net.openid.conformance.openbanking_brasil.creditOperations.discountedCreditRights;

import com.google.gson.JsonObject;
import net.openid.conformance.condition.PreEnvironment;
import net.openid.conformance.condition.client.AbstractJsonAssertingCondition;
import net.openid.conformance.logging.ApiName;
import net.openid.conformance.testmodule.Environment;

/**
 * This is validator for API Credit Operations/Discounted Credit Rights "
 * See https://openbanking-brasil.github.io/areadesenvolvedor/#direitos-creditorios-descontados
 **/

@ApiName("Invoice Financing Contracts")
public class InvoiceFinancingContractsResponseValidator extends AbstractJsonAssertingCondition {

	@Override
	@PreEnvironment(strings = "resource_endpoint_response")
	public Environment evaluate(Environment environment) {
		JsonObject body = bodyFrom(environment);

		assertHasField(body, "$.data");
		assertHasStringField(body, "$.data[0].contractId");
		assertHasStringField(body, "$.data[0].brandName");
		assertHasStringField(body, "$.data[0].companyCnpj");
		assertHasStringField(body, "$.data[0].productType");
		assertHasStringField(body, "$.data[0].productSubType");
		assertHasStringField(body, "$.data[0].ipocCode");

		return environment;
	}
}