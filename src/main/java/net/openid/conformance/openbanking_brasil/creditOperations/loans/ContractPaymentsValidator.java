package net.openid.conformance.openbanking_brasil.creditOperations.loans;

import com.google.gson.JsonObject;
import net.openid.conformance.condition.PreEnvironment;
import net.openid.conformance.condition.client.AbstractJsonAssertingCondition;
import net.openid.conformance.logging.ApiName;
import net.openid.conformance.testmodule.Environment;

/**
 * This is validator for API - Operações de Crédito - Empréstimos| Pagamentos do Contrato
 * See <a href="https://openbanking-brasil.github.io/areadesenvolvedor/#emprestimos-pagamentos-do-contrato">Empréstimos - Pagamentos do Contrato</a>
 **/

@ApiName("Contract Payments")
public class ContractPaymentsValidator extends AbstractJsonAssertingCondition {

	@Override
	@PreEnvironment(strings = "resource_endpoint_response")
	public Environment evaluate(Environment environment) {

		JsonObject body = bodyFrom(environment);
		assertHasField(body, "$.data");

		assertHasIntField(body,"$.data.paidInstalments");
		assertHasDoubleField(body,"$.data.contractOutstandingBalance");

		assertHasField(body,"$.data.releases[0]");
		assertHasStringField(body,"$.data.releases[0].paymentId");
		assertHasBooleanField(body,"$.data.releases[0].isOverParcelPayment");
		assertHasStringField(body,"$.data.releases[0].instalmentId");
		assertHasStringField(body,"$.data.releases[0].paidDate");
		assertHasStringField(body,"$.data.releases[0].currency");
		assertHasDoubleField(body,"$.data.releases[0].paidAmount");

		assertHasField(body,"$.data.releases[0].overParcel");

		assertHasField(body,"$.data.releases[0].overParcel.fees[0]");
		assertHasStringField(body,"$.data.releases[0].overParcel.fees[0].feeName");
		assertHasStringField(body,"$.data.releases[0].overParcel.fees[0].feeCode");
		assertHasDoubleField(body,"$.data.releases[0].overParcel.fees[0].feeAmount");

		assertHasField(body,"$.data.releases[0].overParcel.charges[0]");
		assertHasStringField(body,"$.data.releases[0].overParcel.charges[0].chargeType");
		assertHasStringField(body,"$.data.releases[0].overParcel.charges[0].chargeAdditionalInfo");
		assertHasDoubleField(body,"$.data.releases[0].overParcel.charges[0].chargeAmount");

		return environment;
	}
}