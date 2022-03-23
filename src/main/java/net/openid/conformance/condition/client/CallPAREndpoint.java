package net.openid.conformance.condition.client;

import com.google.common.base.Strings;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.condition.PostEnvironment;
import net.openid.conformance.condition.PreEnvironment;
import net.openid.conformance.testmodule.Environment;
import net.openid.conformance.testmodule.OIDFJSON;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;

/**
 * This class makes a http post to PAR endpoint and the response is stored in the ENV
 */
public class CallPAREndpoint extends AbstractCondition {

	public static final String HTTP_METHOD_KEY = "par_endpoint_http_method";

	@Override
	@PreEnvironment(required = {"server", "pushed_authorization_request_form_parameters"})
	@PostEnvironment(required = {"pushed_authorization_endpoint_response", "pushed_authorization_endpoint_response_headers"})
	public Environment evaluate(Environment env) {

		// build up the form
		JsonObject formJson = env.getObject("pushed_authorization_request_form_parameters");
		MultiValueMap <String, String> form = new LinkedMultiValueMap <>();
		for (String key : formJson.keySet()) {
			JsonElement el = formJson.get(key);
			if (el.isJsonObject()) {
				// e.g. claims parameter
				form.add(key, el.toString());
			} else {
				form.add(key, OIDFJSON.getString(el));
			}
		}

		try {
			RestTemplate restTemplate = createRestTemplate(env);

			HttpHeaders headers = new HttpHeaders();
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

			HttpEntity <MultiValueMap <String, String>> request = new HttpEntity <>(form, headers);

			String jsonString = null;
			HttpMethod httpMethod = env.getString(HTTP_METHOD_KEY) == null ?
				HttpMethod.POST : HttpMethod.valueOf(env.getString(HTTP_METHOD_KEY));

			try {
				String parEndpointUri = null;
				if (env.containsObject("mutual_tls_authentication")) {
					// the MTLS aliased endpoint if we have MTLS authentication available.
					// This is to cater for private_key_jwt (where we should not use the alias) and mtls client auth
					// (where we should); it assumes the caller only supplies mutual_tls_authentication for the calls
					// it is required for.
					// I think here we could just call env.getString("server", "mtls_endpoint_aliases.pushed_authorization_request_endpoint");
					// but https://gitlab.com/openid/conformance-suite/-/issues/914 is open to reconsider the overall
					// mechanism.
					parEndpointUri = env.getString("pushed_authorization_request_endpoint");
				}

				if (parEndpointUri == null) {
					parEndpointUri = env.getString("server", "pushed_authorization_request_endpoint");
				}
				if (Strings.isNullOrEmpty(parEndpointUri)) {
					throw error("Couldn't find pushed_authorization_request_endpoint in server discovery document. This endpoint is required as you have selected to test pushed authorization requests.");
				}

				restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
					@Override
					public boolean hasError(ClientHttpResponse response) throws IOException {
						// Treat all http status codes as 'not an error', so spring never throws an exception due to the http
						// status code meaning the rest of our code can handle http status codes how it likes
						return false;
					}
				});

				ResponseEntity <String> response = restTemplate
					.exchange(parEndpointUri, httpMethod, request, String.class);

				logSuccess("Storing pushed_authorization_endpoint_response_http_status " + response.getStatusCode().value());

				env.putInteger("pushed_authorization_endpoint_response_http_status", response.getStatusCodeValue());

				JsonObject responseHeaders = mapToJsonObject(response.getHeaders(), true);

				env.putObject("pushed_authorization_endpoint_response_headers", responseHeaders);

				jsonString = response.getBody();

			} catch (RestClientResponseException e) {
				throw error("RestClientResponseException occurred whilst calling pushed authorization request endpoint",
					args("code", e.getRawStatusCode(), "status", e.getStatusText(), "body", e.getResponseBodyAsString()));
			} catch (RestClientException e) {
				return handleClientException(env, e);
			}

			if (!httpMethod.equals(HttpMethod.POST)) {
				env.putObject("pushed_authorization_endpoint_response", new JsonObject());
				return env;
			}

			if (Strings.isNullOrEmpty(jsonString)) {
				throw error("Missing or empty response from the pushed authorization request endpoint");
			}

			try {
				JsonElement jsonRoot = JsonParser.parseString(jsonString);
				if (jsonRoot == null || !jsonRoot.isJsonObject()) {
					throw error("Pushed Authorization did not return a JSON object");
				}

				logSuccess("Parsed pushed authorization request endpoint response", jsonRoot.getAsJsonObject());

				env.putObject("pushed_authorization_endpoint_response", jsonRoot.getAsJsonObject());

				return env;
			} catch (JsonParseException e) {
				throw error(e);
			}
		} catch (NoSuchAlgorithmException | KeyManagementException | CertificateException | InvalidKeySpecException | KeyStoreException | IOException | UnrecoverableKeyException e) {
			throw error("Error creating HTTP Client", e);
		}
	}

	protected Environment handleClientException(Environment env, RestClientException e) {
		String msg = "Call to pushed authorization request endpoint failed";
		if (e.getCause() != null) {
			msg += " - " + e.getCause().getMessage();
		}
		throw error(msg, e);
	}
}
