package net.openid.conformance.openbanking_brasil.testmodules.support.payments;

import com.google.gson.JsonObject;
import net.openid.conformance.testmodule.Environment;

public class EnsureConsentErrorWasAgendamantoInvalido extends AbstractErrorFromJwtResponseCondition  {

	public static final String EXPECTED_ERROR = "AGENDAMENTO_INVALIDO";

	@Override
	public Environment evaluate(Environment env) {

		JsonObject response = env.getObject("consent_endpoint_response_full");
		validateError(response, EXPECTED_ERROR);

		return env;
	}

}