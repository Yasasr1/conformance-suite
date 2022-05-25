package net.openid.conformance.condition.client;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.testmodule.Environment;

import java.text.ParseException;

public abstract class AbstractExtractJWKsFromClientConfiguration extends AbstractCondition {
	protected void extractJwks(Environment env, JsonElement jwks) {

		if (jwks == null) {
			throw error("Couldn't find JWKs in client configuration");
		} else if (!(jwks instanceof JsonObject)) {
			throw error("Invalid JWKs in client configuration - JSON decode failed");
		}

		JWKSet parsed;

		if (!jwks.isJsonObject()) {
			throw error("The client jwks is not a JSON object", args("jwks", jwks));
		}

		if (((JsonObject) jwks).has("keys")) {
			try {
				parsed = JWKSet.parse(jwks.toString());
			} catch (ParseException e) {
				throw error("Invalid JWKS in client configuration: " + e.getMessage(),
					e, args("client_jwks", jwks));
			}
		} else {
			// try parsing as a jwk; users often have a jwk and often only need one key, so this just makes things
			// easier for them
			try {
				JWK jwk = JWK.parse(jwks.toString());
				parsed = new JWKSet(jwk);
				jwks = JsonParser.parseString(parsed.toString());
			} catch (ParseException e) {
				throw error("Invalid JWK in client configuration: " + e.getMessage(),
					e, args("client_jwks", jwks));
			}
		}


		JWKSet pub = parsed.toPublicJWKSet();

		JsonObject pubObj = (JsonParser.parseString(pub.toString())).getAsJsonObject();

		logSuccess("Extracted client JWK", args("client_jwks", jwks, "public_client_jwks", pubObj));

		env.putObject("client_jwks", jwks.getAsJsonObject());
		env.putObject("client_public_jwks", pubObj.getAsJsonObject());
	}
}
