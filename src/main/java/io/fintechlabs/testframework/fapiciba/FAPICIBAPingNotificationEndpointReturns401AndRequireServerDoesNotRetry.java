package io.fintechlabs.testframework.fapiciba;

import com.google.gson.JsonObject;
import io.fintechlabs.testframework.condition.Condition;
import io.fintechlabs.testframework.condition.client.ExpectServerDoesNotCallNotificationEndpointTwice;
import io.fintechlabs.testframework.testmodule.PublishTestModule;
import io.fintechlabs.testframework.testmodule.Variant;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@PublishTestModule(
	testName = "fapi-ciba-ping-with-mtls-ciba-notification-endpoint-response-401-and-require-server-does-not-retry",
	displayName = "FAPI-CIBA: Ping mode - ciba-notification-endpoint returned a HTTP 401 Unauthorized response, the server does not retry to call the token_endpoint.",
	summary = "The ciba-notification-endpoint will return a HTTP 401 Unauthorized response, the server should not attempt to make the call again thereafter, if it does the test will be failed",
	profile = "FAPI-CIBA",
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.scope",
		"client.jwks",
		"client.hint_type",
		"client.hint_value",
		"mtls.key",
		"mtls.cert",
		"mtls.ca",
		"client2.client_id",
		"client2.scope",
		"client2.jwks",
		"mtls2.key",
		"mtls2.cert",
		"mtls2.ca",
		"resource.resourceUrl"
	},
	notApplicableForVariants = {
		FAPICIBA.variant_poll_mtls,
		FAPICIBA.variant_poll_privatekeyjwt,
		FAPICIBA.variant_openbankinguk_poll_mtls,
		FAPICIBA.variant_openbankinguk_poll_privatekeyjwt
	}
)
public class FAPICIBAPingNotificationEndpointReturns401AndRequireServerDoesNotRetry extends AbstractFAPICIBA {

	@Variant(name = variant_ping_mtls)
	public void setupPingMTLS() {
		super.setupPingMTLS();
	}

	@Variant(name = variant_ping_privatekeyjwt)
	public void setupPingPrivateKeyJwt() {
		super.setupPingPrivateKeyJwt();
	}

	@Variant(name = variant_openbankinguk_ping_mtls)
	public void setupOpenBankingUkPingMTLS() {
		super.setupOpenBankingUkPingMTLS();
	}

	@Variant(name = variant_openbankinguk_ping_privatekeyjwt)
	public void setupOpenBankingUkPingPrivateKeyJwt() {
		super.setupOpenBankingUkPingPrivateKeyJwt();
	}

	@Override
	protected Object handlePingCallback(JsonObject requestParts) {

		callAndContinueOnFailure(ExpectServerDoesNotCallNotificationEndpointTwice.class, Condition.ConditionResult.FAILURE, "CIBA-10.2");

		String calledTimes = env.getString("times_server_called_notification_endpoint");
		if(Integer.valueOf(calledTimes) == 1) {

			setStatus(Status.RUNNING);

			getTestExecutionManager().runInBackground(() -> {

				// Wait for 5 second and then process notification callback as normal
				Thread.sleep(5 * 1000);

				setStatus(Status.RUNNING);

				processNotificationCallback(requestParts);

				return "done";
			});

			setStatus(Status.WAITING);

			return new ResponseEntity<Object>("CIBA Notification Endpoint returns a HTTP 401 Unauthorized response, even though the token is valid.", HttpStatus.UNAUTHORIZED);
		} else {
			return new ResponseEntity<Object>("", HttpStatus.NO_CONTENT);
		}
	}
}