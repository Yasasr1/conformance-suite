package net.openid.conformance.openbanking_brasil.testmodules.support;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.testmodule.Environment;
import net.openid.conformance.testmodule.OIDFJSON;
import net.openid.conformance.util.JsonUtils;

import java.util.Base64;

public class Ensure422ResponseCodeWasPAGAMENTO_DIVERGENTE_DO_CONSENTIMENTO_OR_NAO_INFORMADO extends AbstractCondition {

	@Override
	public Environment evaluate(Environment env) {

		String jwt = env.getString("resource_endpoint_response");
		String body = jwt.split("\\.")[1];
		body = new String(Base64.getUrlDecoder().decode(body));
		JsonObject json = stringToJson(body);

		JsonArray errors = json.getAsJsonArray("errors");
		JsonObject error = errors.get(0).getAsJsonObject();
		String status = OIDFJSON.getString(error.get("code"));




		if (status.equalsIgnoreCase("PAGAMENTO_DIVERGENTE_DO_CONSENTIMENTO") || (status.equalsIgnoreCase("NAO_INFORMADO"))) {
			logSuccess("Error code is PAGAMENTO_DIVERGENTE_DO_CONSENTIMENTO OR NAO_INFORMADO as expected");
		} else {
			throw error ("Incorrect error code "+ status +". Expected PAGAMENTO_DIVERGENTE_DO_CONSENTIMENTO OR NAO_INFORMADO");
		}
		return env;
	}

	private JsonObject stringToJson(String json){
		Gson gson = JsonUtils.createBigDecimalAwareGson();
		return gson.fromJson(json, JsonObject.class);
	}
}