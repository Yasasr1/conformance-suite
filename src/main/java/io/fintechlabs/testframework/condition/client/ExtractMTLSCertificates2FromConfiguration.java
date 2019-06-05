package io.fintechlabs.testframework.condition.client;

import java.util.regex.Pattern;

import com.google.common.base.Strings;
import com.google.gson.JsonObject;

import io.fintechlabs.testframework.condition.AbstractCondition;
import io.fintechlabs.testframework.condition.PostEnvironment;
import io.fintechlabs.testframework.condition.PreEnvironment;
import io.fintechlabs.testframework.condition.util.PEMFormatter;
import io.fintechlabs.testframework.testmodule.Environment;

public class ExtractMTLSCertificates2FromConfiguration extends AbstractCondition {

	private static final Pattern PEM_PATTERN = Pattern.compile("^-----BEGIN [^-]+-----$(.*?)^-----END [^-]+-----$", Pattern.MULTILINE | Pattern.DOTALL);

	@Override
	@PreEnvironment(required = "config")
	@PostEnvironment(required = "mutual_tls_authentication2")
	public Environment evaluate(Environment env) {

		// mutual_tls_authentication

		String certString = env.getString("config", "mtls2.cert");
		String keyString = env.getString("config", "mtls2.key");
		String caString = env.getString("config", "mtls2.ca");

		if (Strings.isNullOrEmpty(certString) || Strings.isNullOrEmpty(keyString)) {
			throw error("Couldn't find TLS client certificate or key for MTLS");
		}

		if (Strings.isNullOrEmpty(caString)) {
			// Not an error; we just won't send a CA chain
			log("No certificate authority found for MTLS");
		}

		try {
			certString = PEMFormatter.stripPEM(certString);

			keyString = PEMFormatter.stripPEM(keyString);

			if (caString != null) {
				caString = PEMFormatter.stripPEM(caString);
			}
		} catch (IllegalArgumentException e) {
			throw error("Couldn't decode certificate, key, or CA chain from Base64", e, args("cert", certString, "key", keyString, "ca", Strings.emptyToNull(caString)));
		}

		JsonObject mtls = new JsonObject();
		mtls.addProperty("cert", certString);
		mtls.addProperty("key", keyString);
		if (caString != null) {
			mtls.addProperty("ca", caString);
		}

		env.putObject("mutual_tls_authentication2", mtls);

		logSuccess("Mutual TLS authentication credentials loaded", mtls);

		return env;

	}

}
