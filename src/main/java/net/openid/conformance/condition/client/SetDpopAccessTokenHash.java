package net.openid.conformance.condition.client;

import com.google.common.base.Strings;
import com.google.gson.JsonObject;
import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.condition.PreEnvironment;
import net.openid.conformance.testmodule.Environment;
import org.apache.commons.codec.binary.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SetDpopAccessTokenHash extends AbstractCondition {

	@Override
	@PreEnvironment(required = {"dpop_proof_claims", "access_token"})
	public Environment evaluate(Environment env) {

		String accessToken = env.getString("access_token", "value");

		JsonObject claims = env.getObject("dpop_proof_claims");

		byte[] bytes = accessToken.getBytes(StandardCharsets.US_ASCII);
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw error("No such Algorithm Error",e);
		}
		md.update(bytes, 0, bytes.length);
		byte[] digest = md.digest();
		String ath = Base64.encodeBase64URLSafeString(digest);

		claims.addProperty("ath", ath);

		logSuccess("Added ath to DPoP proof claims", args("claims", claims, "access_token", accessToken));

		return env;

	}
}
