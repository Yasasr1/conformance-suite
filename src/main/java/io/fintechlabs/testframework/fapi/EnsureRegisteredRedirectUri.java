package io.fintechlabs.testframework.fapi;

import com.google.gson.JsonObject;

import io.fintechlabs.testframework.condition.ConditionError;
import io.fintechlabs.testframework.condition.client.AddCodeChallengeToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddNonceToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddStateToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.BuildPlainRedirectToAuthorizationEndpoint;
import io.fintechlabs.testframework.condition.client.CreateAuthorizationEndpointRequestFromClientInformation;
import io.fintechlabs.testframework.condition.client.CreateBadRedirectUri;
import io.fintechlabs.testframework.condition.client.CreateRandomCodeVerifier;
import io.fintechlabs.testframework.condition.client.CreateRandomNonceValue;
import io.fintechlabs.testframework.condition.client.CreateRandomStateValue;
import io.fintechlabs.testframework.condition.client.CreateS256CodeChallenge;
import io.fintechlabs.testframework.condition.client.GetDynamicServerConfiguration;
import io.fintechlabs.testframework.condition.client.GetStaticClientConfiguration;
import io.fintechlabs.testframework.condition.client.SetAuthorizationEndpointRequestResponseTypeToCodeIdtoken;
import io.fintechlabs.testframework.condition.common.CheckServerConfiguration;
import io.fintechlabs.testframework.condition.common.ExpectRedirectUriErrorPage;
import io.fintechlabs.testframework.testmodule.PublishTestModule;
import io.fintechlabs.testframework.testmodule.TestFailureException;

/**
 * Tests that the AS will reject a non-registered redirect URI by
 */
@PublishTestModule(
	testName = "fapi-r-ensure-redirect-uri-is-registered",
	displayName = "FAPI-R: Ensure redirect URI is registered (code id_token)",
	profile = "FAPI-R",
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.scope"
	}
)
public class EnsureRegisteredRedirectUri extends AbstractRedirectServerTestModule {

	/* (non-Javadoc)
	 * @see io.fintechlabs.testframework.testmodule.TestModule#configure(com.google.gson.JsonObject, io.fintechlabs.testframework.logging.EventLog, java.lang.String, io.fintechlabs.testframework.frontChannel.BrowserControl, java.lang.String)
	 */
	@Override
	public void configure(JsonObject config, String baseUrl, String externalUrlOverride) {
		env.putString("base_url", baseUrl);
		env.putObject("config", config);

		// create a random redirect URI
		callAndStopOnFailure(CreateBadRedirectUri.class);

		// this is inserted by the create call above, expose it to the test environment for publication
		exposeEnvString("redirect_uri");

		// Make sure we're calling the right server configuration
		callAndStopOnFailure(GetDynamicServerConfiguration.class);

		// make sure the server configuration passes some basic sanity checks
		callAndStopOnFailure(CheckServerConfiguration.class);

		// Set up the client configuration
		callAndStopOnFailure(GetStaticClientConfiguration.class);

		exposeEnvString("client_id");

		setStatus(Status.CONFIGURED);

		fireSetupDone();
	}

	/* (non-Javadoc)
	 * @see io.fintechlabs.testframework.testmodule.TestModule#start()
	 */
	@Override
	public void start() {
		setStatus(Status.RUNNING);

		callAndStopOnFailure(CreateAuthorizationEndpointRequestFromClientInformation.class);

		callAndStopOnFailure(CreateRandomStateValue.class);
		exposeEnvString("state");
		callAndStopOnFailure(AddStateToAuthorizationEndpointRequest.class);

		callAndStopOnFailure(CreateRandomNonceValue.class);
		exposeEnvString("nonce");
		callAndStopOnFailure(AddNonceToAuthorizationEndpointRequest.class);

		callAndStopOnFailure(SetAuthorizationEndpointRequestResponseTypeToCodeIdtoken.class);

		call(condition(CreateRandomCodeVerifier.class).requirement("RFC7636-4.1"));
		call(exec().exposeEnvironmentString("code_verifier"));
		call(condition(CreateS256CodeChallenge.class));
		call(exec()
			.exposeEnvironmentString("code_challenge")
			.exposeEnvironmentString("code_challenge_method"));
		call(condition(AddCodeChallengeToAuthorizationEndpointRequest.class)
			.requirement("FAPI-R-5.2.2-7"));

		callAndStopOnFailure(BuildPlainRedirectToAuthorizationEndpoint.class);

		performRedirectAndWaitForErrorCallback();
	}

	@Override
	protected void createPlaceholder() {
		callAndStopOnFailure(ExpectRedirectUriErrorPage.class, "FAPI-R-5.2.2-8");

		env.putString("error_callback_placeholder", env.getString("redirect_uri_error"));
	}

	@Override
	protected void processCallback() {

		fireTestFailure();
		throw new TestFailureException(new ConditionError(getId(), "Couldn't ever got the callback response"));
	}
}
