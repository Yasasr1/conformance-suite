package io.fintechlabs.testframework.fapiciba;

import com.google.common.base.Strings;
import com.google.gson.JsonObject;
import io.fintechlabs.testframework.condition.Condition;
import io.fintechlabs.testframework.condition.ConditionError;
import io.fintechlabs.testframework.condition.as.CheckAuthReqIdInCallback;
import io.fintechlabs.testframework.condition.as.CheckNotificationCallbackOnlyAuthReqId;
import io.fintechlabs.testframework.condition.as.VerifyBearerTokenHeaderCallback;
import io.fintechlabs.testframework.condition.client.AddAcrValuesScaToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddAudToRequestObject;
import io.fintechlabs.testframework.condition.client.AddAuthReqIdToTokenEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddCibaGrantTypeToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddCibaRequestSigningPS256ToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddCibaTokenDeliveryModePingToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddCibaUserCodeFalseToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddClientCredentialsGrantTypeToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddClientNotificationTokenToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddEmptyResponseTypesArrayToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddExpToRequestObject;
import io.fintechlabs.testframework.condition.client.AddFAPIInteractionIdToResourceEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddHintToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddIatToRequestObject;
import io.fintechlabs.testframework.condition.client.AddIdTokenSigningAlgPS256ToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddIssToRequestObject;
import io.fintechlabs.testframework.condition.client.AddJtiToRequestObject;
import io.fintechlabs.testframework.condition.client.AddNbfToRequestObject;
import io.fintechlabs.testframework.condition.client.AddNotificationEndpointToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddPublicJwksToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddRequestToBackchannelAuthenticationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddRequestedExp300SToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddScopeToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.AddTLSBoundAccessTokensTrueToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.AddTokenEndpointAuthMethodSelfSignedTlsToDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.CIBANotificationEndpointCalledUnexpectedly;
import io.fintechlabs.testframework.condition.client.CallAccountRequestsEndpointWithBearerToken;
import io.fintechlabs.testframework.condition.client.CallAccountsEndpointWithBearerToken;
import io.fintechlabs.testframework.condition.client.CallAccountsEndpointWithBearerTokenExpectingError;
import io.fintechlabs.testframework.condition.client.CallAutomatedCibaApprovalEndpoint;
import io.fintechlabs.testframework.condition.client.CallBackchannelAuthenticationEndpoint;
import io.fintechlabs.testframework.condition.client.CallDynamicRegistrationEndpoint;
import io.fintechlabs.testframework.condition.client.CallTokenEndpoint;
import io.fintechlabs.testframework.condition.client.CallTokenEndpointAndReturnFullResponse;
import io.fintechlabs.testframework.condition.client.CheckBackchannelAuthenticationEndpointContentType;
import io.fintechlabs.testframework.condition.client.CheckBackchannelAuthenticationEndpointHttpStatus200;
import io.fintechlabs.testframework.condition.client.CheckBackchannelAuthenticationEndpointHttpStatus400;
import io.fintechlabs.testframework.condition.client.CheckErrorFromTokenEndpointResponseErrorInvalidGrant;
import io.fintechlabs.testframework.condition.client.CheckForAccessTokenValue;
import io.fintechlabs.testframework.condition.client.CheckForDateHeaderInResourceResponse;
import io.fintechlabs.testframework.condition.client.CheckForFAPIInteractionIdInResourceResponse;
import io.fintechlabs.testframework.condition.client.CheckForRefreshTokenValue;
import io.fintechlabs.testframework.condition.client.CheckForScopesInTokenResponse;
import io.fintechlabs.testframework.condition.client.CheckForSubjectInIdToken;
import io.fintechlabs.testframework.condition.client.CheckIfAccountRequestsEndpointResponseError;
import io.fintechlabs.testframework.condition.client.CheckIfBackchannelAuthenticationEndpointResponseError;
import io.fintechlabs.testframework.condition.client.CheckIfTokenEndpointResponseError;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointCacheHeaders;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointHttpStatus200;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointHttpStatus400;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointHttpStatus503;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointHttpStatusNot200;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointRetryAfterHeaders;
import io.fintechlabs.testframework.condition.client.CheckTokenEndpointReturnedJsonContentType;
import io.fintechlabs.testframework.condition.client.ConvertAuthorizationEndpointRequestToRequestObject;
import io.fintechlabs.testframework.condition.client.CopyScopeFromDynamicRegistrationTemplateToClientConfiguration;
import io.fintechlabs.testframework.condition.client.CreateBackchannelAuthenticationEndpointRequest;
import io.fintechlabs.testframework.condition.client.CreateCIBANotificationEndpointUri;
import io.fintechlabs.testframework.condition.client.CreateCreateAccountRequestRequest;
import io.fintechlabs.testframework.condition.client.CreateDynamicRegistrationRequest;
import io.fintechlabs.testframework.condition.client.CreateEmptyAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.CreateLongRandomClientNotificationToken;
import io.fintechlabs.testframework.condition.client.CreateRandomClientNotificationToken;
import io.fintechlabs.testframework.condition.client.CreateRandomFAPIInteractionId;
import io.fintechlabs.testframework.condition.client.CreateTokenEndpointRequestForCIBAGrant;
import io.fintechlabs.testframework.condition.client.CreateTokenEndpointRequestForClientCredentialsGrant;
import io.fintechlabs.testframework.condition.client.DisallowAccessTokenInQuery;
import io.fintechlabs.testframework.condition.client.EnsureErrorTokenEndpointSlowdownOrAuthorizationPending;
import io.fintechlabs.testframework.condition.client.EnsureMatchingFAPIInteractionId;
import io.fintechlabs.testframework.condition.client.EnsureMinimumAuthenticationRequestIdEntropy;
import io.fintechlabs.testframework.condition.client.EnsureMinimumAuthenticationRequestIdLength;
import io.fintechlabs.testframework.condition.client.EnsureMinimumTokenEntropy;
import io.fintechlabs.testframework.condition.client.EnsureMinimumTokenLength;
import io.fintechlabs.testframework.condition.client.EnsureRecommendedAuthenticationRequestIdEntropy;
import io.fintechlabs.testframework.condition.client.EnsureResourceResponseContentTypeIsJsonUTF8;
import io.fintechlabs.testframework.condition.client.ExpectExpiredTokenErrorFromTokenEndpoint;
import io.fintechlabs.testframework.condition.client.ExtractAccessTokenFromTokenResponse;
import io.fintechlabs.testframework.condition.client.ExtractAccountRequestIdFromAccountRequestsEndpointResponse;
import io.fintechlabs.testframework.condition.client.ExtractAtHash;
import io.fintechlabs.testframework.condition.client.ExtractExpiresInFromTokenEndpointResponse;
import io.fintechlabs.testframework.condition.client.ExtractIdTokenFromTokenResponse;
import io.fintechlabs.testframework.condition.client.ExtractJWKsFromDynamicClientConfiguration;
import io.fintechlabs.testframework.condition.client.ExtractJWKsFromStaticClientConfiguration;
import io.fintechlabs.testframework.condition.client.ExtractMTLSCertificates2FromConfiguration;
import io.fintechlabs.testframework.condition.client.ExtractMTLSCertificatesFromConfiguration;
import io.fintechlabs.testframework.condition.client.ExtractRtHash;
import io.fintechlabs.testframework.condition.client.ExtractTLSTestValuesFromOBResourceConfiguration;
import io.fintechlabs.testframework.condition.client.ExtractTLSTestValuesFromResourceConfiguration;
import io.fintechlabs.testframework.condition.client.ExtractTLSTestValuesFromServerConfiguration;
import io.fintechlabs.testframework.condition.client.FAPICIBAValidateIdTokenACRClaims;
import io.fintechlabs.testframework.condition.client.FAPICIBAValidateIdTokenAuthRequestIdClaims;
import io.fintechlabs.testframework.condition.client.FAPICIBAValidateRtHash;
import io.fintechlabs.testframework.condition.client.FAPIGenerateResourceEndpointRequestHeaders;
import io.fintechlabs.testframework.condition.client.FAPIValidateIdTokenSigningAlg;
import io.fintechlabs.testframework.condition.client.FetchServerKeys;
import io.fintechlabs.testframework.condition.client.GetDynamicClient2Configuration;
import io.fintechlabs.testframework.condition.client.GetDynamicClientConfiguration;
import io.fintechlabs.testframework.condition.client.GetDynamicServerConfiguration;
import io.fintechlabs.testframework.condition.client.GetResourceEndpointConfiguration;
import io.fintechlabs.testframework.condition.client.GetStaticClient2Configuration;
import io.fintechlabs.testframework.condition.client.GetStaticClientConfiguration;
import io.fintechlabs.testframework.condition.client.SetAccountScopeOnTokenEndpointRequest;
import io.fintechlabs.testframework.condition.client.SetPermissiveAcceptHeaderForResourceEndpointRequest;
import io.fintechlabs.testframework.condition.client.SetPlainJsonAcceptHeaderForResourceEndpointRequest;
import io.fintechlabs.testframework.condition.client.SignAuthenticationRequest;
import io.fintechlabs.testframework.condition.client.TellUserToDoCIBAAuthentication;
import io.fintechlabs.testframework.condition.client.ValidateAtHash;
import io.fintechlabs.testframework.condition.client.ValidateAuthenticationRequestId;
import io.fintechlabs.testframework.condition.client.ValidateAuthenticationRequestIdExpiresIn;
import io.fintechlabs.testframework.condition.client.ValidateAuthenticationRequestIdInterval;
import io.fintechlabs.testframework.condition.client.ValidateErrorDescriptionFromBackchannelAuthenticationEndpoint;
import io.fintechlabs.testframework.condition.client.ValidateErrorDescriptionFromTokenEndpointResponseError;
import io.fintechlabs.testframework.condition.client.ValidateErrorFromTokenEndpointResponseError;
import io.fintechlabs.testframework.condition.client.ValidateErrorResponseFromBackchannelAuthenticationEndpoint;
import io.fintechlabs.testframework.condition.client.ValidateErrorUriFromBackchannelAuthenticationEndpoint;
import io.fintechlabs.testframework.condition.client.ValidateErrorUriFromTokenEndpointResponseError;
import io.fintechlabs.testframework.condition.client.ValidateExpiresIn;
import io.fintechlabs.testframework.condition.client.ValidateIdToken;
import io.fintechlabs.testframework.condition.client.ValidateIdTokenNotIncludeCHashAndSHash;
import io.fintechlabs.testframework.condition.client.ValidateIdTokenSignature;
import io.fintechlabs.testframework.condition.client.ValidateMTLSCertificates2Header;
import io.fintechlabs.testframework.condition.client.ValidateMTLSCertificatesAsX509;
import io.fintechlabs.testframework.condition.client.ValidateMTLSCertificatesHeader;
import io.fintechlabs.testframework.condition.common.CheckForKeyIdInClientJWKs;
import io.fintechlabs.testframework.condition.common.CheckForKeyIdInServerJWKs;
import io.fintechlabs.testframework.condition.common.CheckServerConfiguration;
import io.fintechlabs.testframework.condition.common.DisallowInsecureCipher;
import io.fintechlabs.testframework.condition.common.DisallowTLS10;
import io.fintechlabs.testframework.condition.common.DisallowTLS11;
import io.fintechlabs.testframework.condition.common.EnsureIncomingTls12;
import io.fintechlabs.testframework.condition.common.EnsureIncomingTlsSecureCipher;
import io.fintechlabs.testframework.condition.common.EnsureTLS12;
import io.fintechlabs.testframework.condition.common.FAPICheckKeyAlgInClientJWKs;
import io.fintechlabs.testframework.sequence.ConditionSequence;
import io.fintechlabs.testframework.sequence.client.AddMTLSClientAuthenticationToBackchannelRequest;
import io.fintechlabs.testframework.sequence.client.AddMTLSClientAuthenticationToTokenEndpointRequest;
import io.fintechlabs.testframework.sequence.client.AddPrivateKeyJWTClientAuthenticationToBackchannelRequest;
import io.fintechlabs.testframework.sequence.client.AddPrivateKeyJWTClientAuthenticationToTokenEndpointRequest;
import io.fintechlabs.testframework.testmodule.AbstractTestModule;
import io.fintechlabs.testframework.testmodule.TestFailureException;
import io.fintechlabs.testframework.testmodule.UserFacing;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public abstract class AbstractFAPICIBA extends AbstractTestModule {

	private static final Logger logger = LoggerFactory.getLogger(AbstractFAPICIBA.class);
	protected int whichClient;
	protected enum TestType {
		PING,
		POLL
	}
	protected TestType testType;

	/* to be used in @Variant definitions */
	protected final String variant_ping_mtls = "ping-mtls";
	protected final String variant_ping_privatekeyjwt = "ping-private_key_jwt";
	protected final String variant_poll_mtls = "poll-mtls";
	protected final String variant_poll_privatekeyjwt = "poll-private_key_jwt";

	/* for subclasses to fill in */
	Class<? extends ConditionSequence> addBackchannelClientAuthentication;
	Class<? extends ConditionSequence> addTokenEndpointClientAuthentication;

	protected void addClientAuthenticationToBackchannelRequest() {
		/* This function can be inlined once all CIBA test modules are using Variants */
		call(sequence(addBackchannelClientAuthentication));
	}

	protected void addClientAuthenticationToTokenEndpointRequest() {
		/* This function can be inlined once all CIBA test modules are using Variants */
		call(sequence(addTokenEndpointClientAuthentication));
	}

	protected void createClientCredentialsRequest() {

		callAndStopOnFailure(CreateTokenEndpointRequestForClientCredentialsGrant.class);
		callAndStopOnFailure(SetAccountScopeOnTokenEndpointRequest.class);

		addClientAuthenticationToTokenEndpointRequest();
	}

	public void registerClient() {

		callAndStopOnFailure(ExtractJWKsFromDynamicClientConfiguration.class);

		// create basic dynamic registration request
		callAndStopOnFailure(CreateDynamicRegistrationRequest.class);
		expose("client_name", env.getString("dynamic_registration_request", "client_name"));

		callAndStopOnFailure(AddCibaGrantTypeToDynamicRegistrationRequest.class, "CIBA-4");
		callAndStopOnFailure(AddClientCredentialsGrantTypeToDynamicRegistrationRequest.class, "OBRW-4.3.1");
		callAndStopOnFailure(AddNotificationEndpointToDynamicRegistrationRequest.class, "CIBA-4");
		callAndStopOnFailure(AddPublicJwksToDynamicRegistrationRequest.class, "RFC7591-2");
		callAndStopOnFailure(AddCibaUserCodeFalseToDynamicRegistrationRequest.class);
		// TODO: for now this only works for 'ping'
		callAndStopOnFailure(AddCibaTokenDeliveryModePingToDynamicRegistrationRequest.class);
		callAndStopOnFailure(AddCibaRequestSigningPS256ToDynamicRegistrationRequest.class);
		callAndStopOnFailure(AddIdTokenSigningAlgPS256ToDynamicRegistrationRequest.class);
		callAndStopOnFailure(AddEmptyResponseTypesArrayToDynamicRegistrationRequest.class);
		callAndStopOnFailure(AddTokenEndpointAuthMethodSelfSignedTlsToDynamicRegistrationRequest.class);
		callAndStopOnFailure(AddTLSBoundAccessTokensTrueToDynamicRegistrationRequest.class);

		callAndStopOnFailure(CallDynamicRegistrationEndpoint.class);

		// TODO: we currently do little verification of the dynamic registration response

		// The tests expect scope to be part of the 'client' object, but it's not part of DCR so we need to manually
		// copy it across.
		callAndStopOnFailure(CopyScopeFromDynamicRegistrationTemplateToClientConfiguration.class);

		// TODO: at the end of the test, delete the client
		// IF management interface, delete the client to clean up
//		skipIfMissing(null,
//			new String[] {"registration_client_uri", "registration_access_token"},
//			Condition.ConditionResult.INFO,
//			UnregisterDynamicallyRegisteredClient.class);
	}

	@Override
	public void configure(JsonObject config, String baseUrl, String externalUrlOverride) {
		env.putString("base_url", baseUrl);
		env.putString("external_url_override", externalUrlOverride);
		env.putObject("config", config);

		callAndStopOnFailure(CreateCIBANotificationEndpointUri.class);

		// this is inserted by the create call above, expose it to the test environment for publication
		exposeEnvString("notification_uri");

		// Make sure we're calling the right server configuration
		callAndStopOnFailure(GetDynamicServerConfiguration.class);

		// make sure the server configuration passes some basic sanity checks
		callAndStopOnFailure(CheckServerConfiguration.class);

		callAndStopOnFailure(ExtractTLSTestValuesFromServerConfiguration.class);

		callAndStopOnFailure(FetchServerKeys.class);
		callAndStopOnFailure(CheckForKeyIdInServerJWKs.class, "OIDCC-10.1");

		whichClient = 1;

		// Set up the client configuration
		if (env.getElementFromObject("config", "client.client_id") != null) {
			eventLog.startBlock("Verify First client: client_id supplied, assume static client configuration");
			callAndStopOnFailure(GetStaticClientConfiguration.class);
			callAndStopOnFailure(ExtractJWKsFromStaticClientConfiguration.class);
		} else {
			eventLog.startBlock("First client: No client_id in configuration, registering client using dynamic client registration");
			callAndStopOnFailure(GetDynamicClientConfiguration.class);
			registerClient();
		}

		exposeEnvString("client_id");

		callAndStopOnFailure(CheckForKeyIdInClientJWKs.class, "OIDCC-10.1");
		callAndContinueOnFailure(FAPICheckKeyAlgInClientJWKs.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.6");

		callAndContinueOnFailure(ValidateMTLSCertificatesHeader.class, Condition.ConditionResult.WARNING);
		callAndStopOnFailure(ExtractMTLSCertificatesFromConfiguration.class, Condition.ConditionResult.FAILURE);
		callAndStopOnFailure(ValidateMTLSCertificatesAsX509.class, Condition.ConditionResult.FAILURE);
		eventLog.endBlock();

		// It might be more sensible to do this only if/when the test needs a second client
		env.mapKey("client", "client2");
		env.mapKey("client_jwks", "client_jwks2");
		env.mapKey("client_public_jwks", "client_public_jwks2");
		env.mapKey("mutual_tls_authentication", "mutual_tls_authentication2");

		if (env.getElementFromObject("config", "client2.client_id") != null) {
			eventLog.startBlock("Verify Second client: client_id supplied, assume static client configuration");
			callAndStopOnFailure(GetStaticClient2Configuration.class);
			callAndStopOnFailure(ExtractJWKsFromStaticClientConfiguration.class);
		} else {
			eventLog.startBlock("Second client: No client_id in configuration, registering client using dynamic client registration");
			callAndStopOnFailure(GetDynamicClient2Configuration.class);
			registerClient();
		}

		callAndStopOnFailure(CheckForKeyIdInClientJWKs.class, "OIDCC-10.1");
		callAndContinueOnFailure(FAPICheckKeyAlgInClientJWKs.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.6");

		callAndContinueOnFailure(ValidateMTLSCertificates2Header.class, Condition.ConditionResult.WARNING);
		callAndContinueOnFailure(ExtractMTLSCertificates2FromConfiguration.class, Condition.ConditionResult.FAILURE);

		// validate the secondary MTLS keys
		callAndStopOnFailure(ValidateMTLSCertificatesAsX509.class);

		env.unmapKey("client");
		env.unmapKey("client_jwks");
		env.unmapKey("client_public_jwks");
		env.unmapKey("mutual_tls_authentication");

		eventLog.endBlock();

		// Set up the resource endpoint configuration
		callAndStopOnFailure(GetResourceEndpointConfiguration.class);

		callAndStopOnFailure(ExtractTLSTestValuesFromResourceConfiguration.class);
		callAndStopOnFailure(ExtractTLSTestValuesFromOBResourceConfiguration.class);

		callAndStopOnFailure(FAPIGenerateResourceEndpointRequestHeaders.class);

		setStatus(Status.CONFIGURED);

		fireSetupDone();
	}

	@Override
	public void start() {

		getTestExecutionManager().runInBackground(() -> {

			setStatus(Status.RUNNING);

			performAuthorizationFlow();

			return "done";
		});
	}

	protected void performPreAuthorizationSteps() {
		eventLog.startBlock(currentClientString() + "Use client_credentials grant to obtain OpenBanking UK intent_id");

		/* get an openbanking intent id */
		requestClientCredentialsGrant();

		createAccountRequest();

		eventLog.endBlock();
	}

	/** Return which client is in use, for use in block identifiers */
	protected String currentClientString() {
		if (whichClient == 2) {
			return "Second client: ";
		}
		return "";
	}

	protected void createAuthorizationRequest() {

		callAndStopOnFailure(CreateEmptyAuthorizationEndpointRequest.class);
		callAndStopOnFailure(AddScopeToAuthorizationEndpointRequest.class, "CIBA-7.1");
		callAndStopOnFailure(AddHintToAuthorizationEndpointRequest.class, "CIBA-7.1");

		// The spec also defines these parameters that we don't currently set:
		// acr_values
		// binding_message
		// user_code

		if (whichClient == 2) {
			// set a fairly standard requested expiry to verify server doesn't reject it
			callAndStopOnFailure(AddRequestedExp300SToAuthorizationEndpointRequest.class, "CIBA-11");
		}

		modeSpecificAuthorizationEndpointRequest();

		performProfileAuthorizationEndpointSetup();
	}

	protected void createAuthorizationRequestObject() {

		callAndStopOnFailure(ConvertAuthorizationEndpointRequestToRequestObject.class);

		callAndStopOnFailure(AddIatToRequestObject.class, "CIBA-7.1.1");

		callAndStopOnFailure(AddExpToRequestObject.class, "CIBA-7.1.1");

		callAndStopOnFailure(AddNbfToRequestObject.class, "CIBA-7.1.1");

		callAndStopOnFailure(AddJtiToRequestObject.class, "CIBA-7.1.1");

		callAndStopOnFailure(AddAudToRequestObject.class, "CIBA-7.1.1");

		callAndStopOnFailure(AddIssToRequestObject.class, "CIBA-7.1.1");

	}

	protected void performValidateAuthorizationResponse() {

		callAndStopOnFailure(CheckBackchannelAuthenticationEndpointHttpStatus200.class, "CIBA-7.3");

		callAndStopOnFailure(CheckBackchannelAuthenticationEndpointContentType.class, "CIBA-7.3");

		callAndStopOnFailure(CheckIfBackchannelAuthenticationEndpointResponseError.class);

		// https://bitbucket.org/openid/mobile/issues/150/should-auth_req_id-have-limits-on
		callAndStopOnFailure(ValidateAuthenticationRequestId.class, "CIBA-7.3");

		callAndContinueOnFailure(EnsureMinimumAuthenticationRequestIdLength.class, Condition.ConditionResult.FAILURE, "CIBA-7.3");

		callAndContinueOnFailure(EnsureMinimumAuthenticationRequestIdEntropy.class, Condition.ConditionResult.FAILURE, "CIBA-7.3");

		callAndContinueOnFailure(EnsureRecommendedAuthenticationRequestIdEntropy.class, Condition.ConditionResult.WARNING, "CIBA-7.3");

		callAndContinueOnFailure(ValidateAuthenticationRequestIdExpiresIn.class, Condition.ConditionResult.FAILURE,"CIBA-7.3");

		callAndContinueOnFailure(ValidateAuthenticationRequestIdInterval.class, Condition.ConditionResult.FAILURE, "CIBA-7.3");
	}

	protected void validateErrorFromBackchannelAuthorizationRequestResponse() {

		callAndContinueOnFailure(ValidateErrorResponseFromBackchannelAuthenticationEndpoint.class, Condition.ConditionResult.FAILURE, "CIBA-13");

		callAndContinueOnFailure(ValidateErrorUriFromBackchannelAuthenticationEndpoint.class, Condition.ConditionResult.FAILURE, "CIBA-13");

		callAndContinueOnFailure(ValidateErrorDescriptionFromBackchannelAuthenticationEndpoint.class, Condition.ConditionResult.FAILURE, "CIBA-13");

		callAndContinueOnFailure(CheckBackchannelAuthenticationEndpointHttpStatus400.class, Condition.ConditionResult.FAILURE, "CIBA-13");

	}

	protected void performPostAuthorizationResponse() {

		// Call token endpoint; 'ping' mode clients are allowed (but not required) to do this.
		// As there's no way the user could have authenticated this request, we assume we will get a
		// authorization_pending error back
		eventLog.startBlock(currentClientString() + "Call token endpoint expecting pending");
		callTokenEndpointForCibaGrant();
		verifyTokenEndpointResponseIsPendingOrSlowDown();
		eventLog.endBlock();

		long delaySeconds = 5;
		Integer interval = env.getInteger("backchannel_authentication_endpoint_response", "interval");
		if (interval != null && interval > 5) {
			// ignore intervals lower than 5; we don't want to fill the log or exhaust our retries too quickly
			delaySeconds = interval;
		}

		try {
			Thread.sleep(delaySeconds * 1000);
		} catch (InterruptedException e) {
			throw new TestFailureException(getId(), "Thread.sleep threw exception: " + e.getMessage());
		}

		// call token endpoint again and perform same checks exactly as above - but avoiding letting the request expire

		eventLog.startBlock(currentClientString() + "Call token endpoint expecting pending (second time)");
		callTokenEndpointForCibaGrant();
		verifyTokenEndpointResponseIsPendingOrSlowDown();
		eventLog.endBlock();

		String tokenEndpointError = env.getString("token_endpoint_response", "error");
		// slow_down: the interval MUST be increased by at least 5 seconds for this and all subsequent requests
		// delaySeconds is as interval
		if (!Strings.isNullOrEmpty(tokenEndpointError) && tokenEndpointError.equals("slow_down")) {
			delaySeconds = delaySeconds + 5;

			try {
				Thread.sleep(delaySeconds * 1000L);
			} catch (InterruptedException e) {
				throw new TestFailureException(getId(), "Thread.sleep threw exception: " + e.getMessage());
			}
		}

		callAutomatedEndpoint();

		waitForAuthenticationToComplete(delaySeconds);

	}

	protected void performAuthorizationRequest() {

		createAuthorizationRequestObject();

		callAndStopOnFailure(SignAuthenticationRequest.class, "CIBA-7.1.1");

		callAndStopOnFailure(CreateBackchannelAuthenticationEndpointRequest.class, "CIBA-7.1");

		callAndStopOnFailure(AddRequestToBackchannelAuthenticationEndpointRequest.class);

		addClientAuthenticationToBackchannelRequest();

		callAndStopOnFailure(CallBackchannelAuthenticationEndpoint.class);
	}

	protected void performAuthorizationFlow() {
		performPreAuthorizationSteps();

		eventLog.startBlock(currentClientString() + "Call backchannel authentication endpoint");

		createAuthorizationRequest();

		performAuthorizationRequest();

		performValidateAuthorizationResponse();

		eventLog.endBlock();

		performPostAuthorizationResponse();
	}

	protected void waitForPollingAuthenticationToComplete(long delaySeconds) {
		int attempts = 0;
		while (attempts++ < 20) {
			// poll the token endpoint

			setStatus(Status.WAITING);
			try {
				Thread.sleep(delaySeconds * 1000);
			} catch (InterruptedException e) {
				throw new TestFailureException(getId(), "Thread.sleep threw exception: " + e.getMessage());
			}
			setStatus(Status.RUNNING);

			eventLog.startBlock(currentClientString() + "Polling token endpoint waiting for user to authenticate");
			callTokenEndpointForCibaGrant();
			eventLog.endBlock();
			int httpStatus = env.getInteger("token_endpoint_response_http_status");
			if (httpStatus == 200) {
				handleSuccessfulTokenEndpointResponse();
				return;
			}
			verifyTokenEndpointResponseIsPendingOrSlowDown();

			if (delaySeconds < 60) {
				delaySeconds *= 1.5;
			}
		}

		// we never moved out of pending and hence could not complete the test, test fails
		fireTestFailure();
		throw new TestFailureException(new ConditionError(getId(), "User did not authenticate before timeout"));
	}

	protected void requestClientCredentialsGrant() {
		createClientCredentialsRequest();

		callAndStopOnFailure(CallTokenEndpoint.class);

		callAndStopOnFailure(CheckIfTokenEndpointResponseError.class);

		callAndStopOnFailure(CheckForAccessTokenValue.class);

		callAndStopOnFailure(ExtractAccessTokenFromTokenResponse.class);

		callAndContinueOnFailure(ExtractExpiresInFromTokenEndpointResponse.class);
		skipIfMissing(new String[] { "expires_in" }, null, Condition.ConditionResult.INFO,
			ValidateExpiresIn.class, Condition.ConditionResult.FAILURE, "RFC6749-5.1");
	}

	protected void createAccountRequest() {

		callAndStopOnFailure(CreateCreateAccountRequestRequest.class);

		callAndStopOnFailure(CallAccountRequestsEndpointWithBearerToken.class);

		callAndStopOnFailure(CheckIfAccountRequestsEndpointResponseError.class);

		callAndContinueOnFailure(CheckForFAPIInteractionIdInResourceResponse.class, Condition.ConditionResult.FAILURE, "FAPI-R-6.2.1-12");

		callAndStopOnFailure(ExtractAccountRequestIdFromAccountRequestsEndpointResponse.class);
	}

	protected void performProfileAuthorizationEndpointSetup() {
		// Not sure there's a defined way to do these two in CIBA
//	FIXME	callAndStopOnFailure(AddAccountRequestIdToAuthorizationEndpointRequest.class);

		if ( whichClient == 2) {
			callAndStopOnFailure(AddAcrValuesScaToAuthorizationEndpointRequest.class);
		}

	}

	protected void callTokenEndpointForCibaGrant() {
		callAndStopOnFailure(CreateTokenEndpointRequestForCIBAGrant.class);
		callAndStopOnFailure(AddAuthReqIdToTokenEndpointRequest.class);

		addClientAuthenticationToTokenEndpointRequest();

		callAndStopOnFailure(CallTokenEndpointAndReturnFullResponse.class);
		callAndContinueOnFailure(CheckTokenEndpointReturnedJsonContentType.class, Condition.ConditionResult.FAILURE, "OIDCC-3.1.3.4");
	}

	protected void verifyTokenEndpointResponseIsPendingOrSlowDown() {
		eventLog.startBlock(currentClientString() + "Verify token endpoint response is pending or slow_down");

		checkStatusCode400AndValidateErrorFromTokenEndpointResponse();

		callAndStopOnFailure(EnsureErrorTokenEndpointSlowdownOrAuthorizationPending.class);

		eventLog.endBlock();
	}

	protected void verifyTokenEndpointResponseIsTokenExpired() {
		eventLog.startBlock(currentClientString() + "Verify token endpoint response is expired_token");

		checkStatusCode400AndValidateErrorFromTokenEndpointResponse();

		callAndStopOnFailure(ExpectExpiredTokenErrorFromTokenEndpoint.class, "CIBA-11");

		eventLog.endBlock();
	}

	protected void verifyTokenEndpointResponseIs503Error() {
		eventLog.startBlock(currentClientString() + "Verify token endpoint response is 503 error");

		callAndStopOnFailure(CheckTokenEndpointHttpStatus503.class);

		validateErrorFromTokenEndpointResponse();

		callAndStopOnFailure(CheckTokenEndpointRetryAfterHeaders.class, "CIBA-11");

		eventLog.endBlock();
	}

	protected void checkStatusCode400AndValidateErrorFromTokenEndpointResponse() {
		callAndStopOnFailure(CheckTokenEndpointHttpStatus400.class, "OIDCC-3.1.3.4");
		validateErrorFromTokenEndpointResponse();
	}

	protected void validateErrorFromTokenEndpointResponse() {
		callAndStopOnFailure(ValidateErrorFromTokenEndpointResponseError.class, "RFC6749-5.2");
		callAndStopOnFailure(ValidateErrorDescriptionFromTokenEndpointResponseError.class,"RFC6749-5.2");
		callAndStopOnFailure(ValidateErrorUriFromTokenEndpointResponseError.class,"RFC6749-5.2");
	}

	protected void handleSuccessfulTokenEndpointResponse() {
		eventLog.startBlock(currentClientString() + "Verify token endpoint response");

		callAndStopOnFailure(CheckTokenEndpointHttpStatus200.class, "RFC6749-5.1");

		callAndContinueOnFailure(CheckTokenEndpointCacheHeaders.class, Condition.ConditionResult.FAILURE, "CIBA-10.1.1", "OIDCC-3.1.3.3", "RFC6749-5.1");

		callAndStopOnFailure(CheckIfTokenEndpointResponseError.class);

		callAndStopOnFailure(CheckForAccessTokenValue.class, "FAPI-R-5.2.2-14");

		callAndStopOnFailure(ExtractAccessTokenFromTokenResponse.class);

		callAndContinueOnFailure(ExtractExpiresInFromTokenEndpointResponse.class);
		skipIfMissing(new String[] { "expires_in" }, null, Condition.ConditionResult.INFO,
			ValidateExpiresIn.class, Condition.ConditionResult.FAILURE, "RFC6749-5.1");

		callAndContinueOnFailure(CheckForScopesInTokenResponse.class, Condition.ConditionResult.FAILURE, "FAPI-R-5.2.2-15");

		callAndContinueOnFailure(CheckForRefreshTokenValue.class);

		callAndContinueOnFailure(EnsureMinimumTokenLength.class, Condition.ConditionResult.FAILURE, "FAPI-R-5.2.2-16");

		callAndContinueOnFailure(EnsureMinimumTokenEntropy.class, Condition.ConditionResult.FAILURE, "FAPI-R-5.2.2-16");

		callAndStopOnFailure(ExtractIdTokenFromTokenResponse.class, "FAPI-R-5.2.2-24");

		callAndStopOnFailure(ValidateIdToken.class, "FAPI-R-5.2.2-24");

		performProfileIdTokenValidation();

		callAndStopOnFailure(ValidateIdTokenSignature.class, "FAPI-R-5.2.2-24");

		callAndStopOnFailure(CheckForSubjectInIdToken.class, "FAPI-R-5.2.2-24", "OB-5.2.2-8");
		callAndContinueOnFailure(FAPIValidateIdTokenSigningAlg.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.6");

		// This is only required in push mode; but if the server for some reason includes it for ping/poll it shoud
		// still be correct
		call(condition(FAPICIBAValidateIdTokenAuthRequestIdClaims.class)
			.skipIfElementMissing("id_token", "claims.urn:openid:params:jwt:claim:auth_req_id")
			.onFail(Condition.ConditionResult.FAILURE)
			.onSkip(Condition.ConditionResult.INFO)
			.requirement("CIBA-10.3.1"));

		callAndContinueOnFailure(ValidateIdTokenNotIncludeCHashAndSHash.class, Condition.ConditionResult.WARNING);

		callAndContinueOnFailure(ExtractAtHash.class, Condition.ConditionResult.INFO, "OIDCC-3.3.2.11");

		callAndContinueOnFailure(ExtractRtHash.class, Condition.ConditionResult.INFO);

		/* these all use 'INFO' if the field isn't present - whether the hash is a may/should/shall is
		 * determined by the Extract*Hash condition
		 */
		skipIfMissing(new String[] { "rt_hash" }, null, Condition.ConditionResult.INFO,
			FAPICIBAValidateRtHash.class, Condition.ConditionResult.FAILURE, "CIBA-10.3.1", "OIDCC-3.3.2.11");

		skipIfMissing(new String[] { "at_hash" }, null, Condition.ConditionResult.INFO,
			ValidateAtHash.class, Condition.ConditionResult.FAILURE, "OIDCC-3.3.2.11");

		performPostAuthorizationFlow();
	}

	protected void performPostAuthorizationFlow() {

		if (whichClient == 1) {

			checkAccountRequestEndpointTLS();

			checkAccountResourceEndpointTLS();

			requestProtectedResource();

			verifyAccessTokenWithResourceEndpointDifferentAcceptHeader();

			setupAndValidateConfigurationOfSecondClient();

			performAuthorizationFlow();

		} else {

			// call the token endpoint and complete the flow
			requestProtectedResource();

			// Switch back to client 1
			eventLog.startBlock("Try Client1 Crypto Keys with Client2 token");
			env.unmapKey("client");
			env.unmapKey("client_jwks");
			env.unmapKey("mutual_tls_authentication");

			// Try client 2's access token with client 1's keys
			callAndContinueOnFailure(CallAccountsEndpointWithBearerTokenExpectingError.class, Condition.ConditionResult.FAILURE, "OB-6.2.1-2");

			eventLog.endBlock();

			eventLog.startBlock("Attempting reuse of client2's auth_req_id (which should fail) then testing if access token is revoked");
			// Re-map to Client 2 keys
			env.mapKey("client", "client2");
			env.mapKey("client_jwks", "client_jwks2");
			env.mapKey("mutual_tls_authentication", "mutual_tls_authentication2");

			// Check access_token still works
			callAndContinueOnFailure(CallAccountsEndpointWithBearerToken.class, Condition.ConditionResult.FAILURE, "RFC7231-5.3.2");

			callAndStopOnFailure(CallTokenEndpointAndReturnFullResponse.class,  "CIBA-11");
			callAndContinueOnFailure(CheckTokenEndpointHttpStatus400.class, Condition.ConditionResult.FAILURE, "OIDCC-3.1.3.4");
			callAndContinueOnFailure(CheckTokenEndpointReturnedJsonContentType.class, Condition.ConditionResult.FAILURE, "OIDCC-3.1.3.4");
			callAndContinueOnFailure(ValidateErrorFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
			callAndContinueOnFailure(ValidateErrorDescriptionFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
			callAndContinueOnFailure(ValidateErrorUriFromTokenEndpointResponseError.class, Condition.ConditionResult.FAILURE, "RFC6749-5.2");
			callAndContinueOnFailure(CheckErrorFromTokenEndpointResponseErrorInvalidGrant.class, Condition.ConditionResult.FAILURE, "CIBA-11");

			// The AS 'SHOULD' have revoked the access token; try it again".
			callAndContinueOnFailure(CallAccountsEndpointWithBearerTokenExpectingError.class, Condition.ConditionResult.WARNING, "RFC6749-4.1.2");
			eventLog.endBlock();

			fireTestFinished();
		}
	}

	protected void setupAndValidateConfigurationOfSecondClient() {
		// Try the second client
		whichClient = 2;

		// get the second client's JWKs
		env.mapKey("client", "client2");
		env.mapKey("client_jwks", "client_jwks2");
		env.mapKey("client_public_jwks", "client_public_jwks2");
		env.mapKey("mutual_tls_authentication", "mutual_tls_authentication2");
	}

	protected void verifyAccessTokenWithResourceEndpointDifferentAcceptHeader() {
		callAndContinueOnFailure(DisallowAccessTokenInQuery.class, Condition.ConditionResult.FAILURE, "FAPI-R-6.2.1-4");

		callAndStopOnFailure(SetPlainJsonAcceptHeaderForResourceEndpointRequest.class);

		callAndStopOnFailure(CallAccountsEndpointWithBearerToken.class, "RFC7231-5.3.2");

		callAndStopOnFailure(SetPermissiveAcceptHeaderForResourceEndpointRequest.class);

		callAndContinueOnFailure(CallAccountsEndpointWithBearerToken.class, Condition.ConditionResult.FAILURE, "RFC7231-5.3.2");
	}

	protected void checkAccountResourceEndpointTLS() {
		eventLog.startBlock("Accounts resource endpoint TLS test");
		env.mapKey("tls", "accounts_resource_endpoint_tls");
		checkEndpointTLS();
		env.unmapKey("tls");
		eventLog.endBlock();
	}

	protected void checkAccountRequestEndpointTLS() {
		eventLog.startBlock("Accounts request endpoint TLS test");
		env.mapKey("tls", "accounts_request_endpoint_tls");
		checkEndpointTLS();
		eventLog.endBlock();
	}

	protected void checkEndpointTLS() {
		callAndContinueOnFailure(EnsureTLS12.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");
		callAndContinueOnFailure(DisallowTLS10.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");
		callAndContinueOnFailure(DisallowTLS11.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-2");
		callAndContinueOnFailure(DisallowInsecureCipher.class, Condition.ConditionResult.FAILURE, "FAPI-RW-8.5-1");
	}


	@Override
	public Object handleHttp(String path, HttpServletRequest req, HttpServletResponse res, HttpSession session, JsonObject requestParts) {

		if (path.equals("ciba-notification-endpoint")) {
			return handlePingCallback(requestParts);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}

	}

	@UserFacing
	protected Object handlePingCallback(JsonObject requestParts) {
		getTestExecutionManager().runInBackground(() -> {

			// process the callback
			setStatus(Status.RUNNING);

			processNotificationCallback(requestParts);

			return "done";
		});

		return new ResponseEntity<Object>("", HttpStatus.NO_CONTENT);
	}

	protected void performProfileIdTokenValidation() {
		// FIXME: CIBA has no way to request the OB intent id...
//		callAndContinueOnFailure(OBValidateIdTokenIntentId.class, Condition.ConditionResult.FAILURE, "OIDCC-2");

		if ( whichClient == 2 ) {
			callAndContinueOnFailure(FAPICIBAValidateIdTokenACRClaims.class, Condition.ConditionResult.WARNING, "CIBA-7.1");
		}

	}

	protected void callAutomatedEndpoint() {
		env.putString("request_action", "allow");
		callAndStopOnFailure(CallAutomatedCibaApprovalEndpoint.class);
	}

	protected void requestProtectedResource() {

		// verify the access token against a protected resource
		eventLog.startBlock(currentClientString() + "Resource server endpoint tests");


		callAndStopOnFailure(FAPIGenerateResourceEndpointRequestHeaders.class);

		callAndStopOnFailure(CreateRandomFAPIInteractionId.class);

		callAndStopOnFailure(AddFAPIInteractionIdToResourceEndpointRequest.class);

		callAndStopOnFailure(CallAccountsEndpointWithBearerToken.class, "FAPI-R-6.2.1-1", "FAPI-R-6.2.1-3");

		callAndContinueOnFailure(CheckForDateHeaderInResourceResponse.class, Condition.ConditionResult.FAILURE, "FAPI-R-6.2.1-11");

		callAndContinueOnFailure(CheckForFAPIInteractionIdInResourceResponse.class, Condition.ConditionResult.FAILURE, "FAPI-R-6.2.1-12");

		callAndContinueOnFailure(EnsureMatchingFAPIInteractionId.class, Condition.ConditionResult.FAILURE, "FAPI-R-6.2.1-12");

		callAndContinueOnFailure(EnsureResourceResponseContentTypeIsJsonUTF8.class, Condition.ConditionResult.FAILURE, "FAPI-R-6.2.1-9", "FAPI-R-6.2.1-10");
	}

	protected void verifyNotificationCallback(JsonObject requestParts){
		String envKey = "notification_callback";

		eventLog.startBlock(currentClientString() + "Verify notification callback");

		env.putObject(envKey, requestParts);

		env.mapKey("client_request", envKey);

		callAndContinueOnFailure(EnsureIncomingTls12.class, "FAPI-R-7.1-1");
		callAndContinueOnFailure(EnsureIncomingTlsSecureCipher.class, Condition.ConditionResult.FAILURE, "FAPI-R-7.1-1");

		env.unmapKey("client_request");

		callAndStopOnFailure(VerifyBearerTokenHeaderCallback.class, "CIBA-10.2");

		callAndStopOnFailure(CheckAuthReqIdInCallback.class, Condition.ConditionResult.FAILURE, "CIBA-10.2");

		callAndStopOnFailure(CheckNotificationCallbackOnlyAuthReqId.class, "CIBA-10.2");
		eventLog.endBlock();
	}

	protected void processPingNotificationCallback(JsonObject requestParts){

		verifyNotificationCallback(requestParts);

		eventLog.startBlock(currentClientString() + "Calling token endpoint after ping notification");
		callTokenEndpointForCibaGrant();
		eventLog.endBlock();
	}

	protected void multipleCallToTokenEndpointAndVerifyResponse(){
		int attempts = 0;
		while (attempts++ < 20) {
			eventLog.startBlock(currentClientString() + "Calling token endpoint expecting one of errors of authorization_pending, slow_down, or 503 error");
			callTokenEndpointForCibaGrant();
			eventLog.endBlock();

			callAndContinueOnFailure(CheckTokenEndpointHttpStatusNot200.class);

			int httpStatus = env.getInteger("token_endpoint_response_http_status");
			if(httpStatus == org.eclipse.jetty.http.HttpStatus.SERVICE_UNAVAILABLE_503){
				verifyTokenEndpointResponseIs503Error();
				return;
			} else {
				verifyTokenEndpointResponseIsPendingOrSlowDown();
			}
		}
	}

	protected void waitForAuthenticationToComplete(long delaySeconds) {
		switch (testType) {
			case PING:
				// for Ping mode:
				callAndStopOnFailure(TellUserToDoCIBAAuthentication.class);

				setStatus(Status.WAITING);
				break;
			case POLL:
				waitForPollingAuthenticationToComplete(delaySeconds);
				break;
			default:
				throw new RuntimeException("unknown testType");
		}

	}

	/** called when the ping notification is received from the authorization server */
	protected void processNotificationCallback(JsonObject requestParts) {
		switch (testType) {
			case PING:
				processPingNotificationCallback(requestParts);
				handleSuccessfulTokenEndpointResponse();
				break;
			case POLL:
				callAndContinueOnFailure(CIBANotificationEndpointCalledUnexpectedly.class, Condition.ConditionResult.FAILURE);
				fireTestFinished();
			default:
				throw new RuntimeException("unknown testType");
		}
	}

	/** This should perform any actions that are specific to whichever of ping/poll/push is being tested */
	protected void modeSpecificAuthorizationEndpointRequest() {
		switch (testType) {
			case PING:
				if ( whichClient == 2 ) {
					callAndStopOnFailure(CreateLongRandomClientNotificationToken.class, "CIBA-7.1", "RFC6750-2.1");
				} else {
					callAndStopOnFailure(CreateRandomClientNotificationToken.class, "CIBA-7.1");
				}

				callAndStopOnFailure(AddClientNotificationTokenToAuthorizationEndpointRequest.class, "CIBA-7.1");
				break;
			case POLL:
				break;
			default:
				throw new RuntimeException("unknown testType");
		}

	}

	public void setupPingMTLS() {
		addBackchannelClientAuthentication = AddMTLSClientAuthenticationToBackchannelRequest.class;
		addTokenEndpointClientAuthentication = AddMTLSClientAuthenticationToTokenEndpointRequest.class;
		testType = TestType.PING;
	}

	public void setupPingPrivateKeyJwt() {
		addBackchannelClientAuthentication = AddPrivateKeyJWTClientAuthenticationToBackchannelRequest.class;
		addTokenEndpointClientAuthentication = AddPrivateKeyJWTClientAuthenticationToTokenEndpointRequest.class;
		testType = TestType.PING;
	}

	public void setupPollMTLS() {
		addBackchannelClientAuthentication = AddMTLSClientAuthenticationToBackchannelRequest.class;
		addTokenEndpointClientAuthentication = AddMTLSClientAuthenticationToTokenEndpointRequest.class;
		testType = TestType.POLL;
	}

	public void setupPollPrivateKeyJwt() {
		addBackchannelClientAuthentication = AddPrivateKeyJWTClientAuthenticationToBackchannelRequest.class;
		addTokenEndpointClientAuthentication = AddPrivateKeyJWTClientAuthenticationToTokenEndpointRequest.class;
		testType = TestType.POLL;
	}

}
