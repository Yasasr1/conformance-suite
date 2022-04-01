package net.openid.conformance.openbanking_brasil.testmodules.support;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.testmodule.Environment;
import net.openid.conformance.testmodule.OIDFJSON;

public class Ensure422ResponseCodeWasDETALHE_PGTO_INVALIDO extends AbstractCondition {

	@Override
	public Environment evaluate(Environment env) {
		JsonObject resourceEndpointResponse = env.getObject("resource_endpoint_response");
		JsonArray errors = resourceEndpointResponse.getAsJsonArray("errors");

		String status = OIDFJSON.getString(errors.get(0).getAsJsonObject().get("code"));

		if (status.equalsIgnoreCase("DETALHE_PGTO_INVALIDO")) {
			logSuccess("Error code is DETALHE_PGTO_INVALIDO as expected");
		} else if (status.equalsIgnoreCase("NAO_INFORMADO")){
			env.putString("warning_message", "Participant returned " + status + " this is accepted behaviour in the specs but awaiting clarification if this is correct");
		} else {
			throw error ("Incorrect error code "+ status);
		}
		return env;
	}
}