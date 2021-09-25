package net.openid.conformance.fapi1advancedfinal;

import com.google.gson.JsonObject;
import net.openid.conformance.condition.Condition;
import net.openid.conformance.condition.as.CheckForClientCertificate;
import net.openid.conformance.condition.as.EnsureMatchingRedirectUriInRequestObject;
import net.openid.conformance.condition.as.EnsureRedirectUriInRequestObjectMatchesOneOfClientRedirectUris;
import net.openid.conformance.condition.as.ExtractClientCertificateFromTokenEndpointRequestHeaders;
import net.openid.conformance.condition.as.FetchClientKeys;
import net.openid.conformance.condition.as.ValidateRedirectUri;
import net.openid.conformance.condition.as.ValidateRedirectUriForTokenEndpointRequest;
import net.openid.conformance.condition.as.dynregistration.EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet;
import net.openid.conformance.condition.as.dynregistration.EnsureRequestObjectEncryptionAlgIsSetIfEncIsSet;
import net.openid.conformance.condition.as.dynregistration.EnsureUserinfoEncryptedResponseAlgIsSetIfEncIsSet;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilEnsureClientMetadataMatchSoftwareStatement;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilEnsureJwksUriMatchesSoftwareJwksUri;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilEnsureRedirectUrisMatchSoftwareRedirectUris;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilEnsureRegistrationRequestDoesNotIncludeJwks;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilExtractSSAFromDynamicRegistrationRequest;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilExtractSoftwareStatement;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilFetchDirectorySSAJwks;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilRegisterClient;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateClientAuthenticationMethods;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateDefaultAcrValues;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateIdTokenSignedResponseAlg;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateRequestObjectEncryption;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateRequestObjectSigningAlg;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateSSASignature;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateSoftwareStatementIat;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateTokenEndpointAuthSigningAlg;
import net.openid.conformance.condition.as.dynregistration.FAPIBrazilValidateUserinfoSignedResponseAlg;
import net.openid.conformance.condition.as.dynregistration.OIDCCExtractDynamicRegistrationRequest;
import net.openid.conformance.condition.as.dynregistration.OIDCCValidateClientRedirectUris;
import net.openid.conformance.condition.as.dynregistration.ValidateClientGrantTypes;
import net.openid.conformance.condition.as.dynregistration.ValidateClientLogoUris;
import net.openid.conformance.condition.as.dynregistration.ValidateClientPolicyUris;
import net.openid.conformance.condition.as.dynregistration.ValidateClientSubjectType;
import net.openid.conformance.condition.as.dynregistration.ValidateClientTosUris;
import net.openid.conformance.condition.as.dynregistration.ValidateClientUris;
import net.openid.conformance.condition.as.dynregistration.ValidateDefaultMaxAge;
import net.openid.conformance.condition.as.dynregistration.ValidateInitiateLoginUri;
import net.openid.conformance.condition.as.dynregistration.ValidateRequireAuthTime;
import net.openid.conformance.condition.as.dynregistration.ValidateUserinfoSignedResponseAlg;
import net.openid.conformance.condition.common.EnsureIncomingTls12WithSecureCipherOrTls13;
import net.openid.conformance.testmodule.PublishTestModule;
import net.openid.conformance.variant.FAPIAuthRequestMethod;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@PublishTestModule(
	testName = "fapi1-advanced-final-client-brazildcr-happypath-test",
	displayName = "FAPI1-Advanced-Final: client DCR happy path test",
	summary = "Tests a 'happy path' flow; " +
		"first perform OpenID discovery from the displayed discoveryUrl, and register the client. " +
		"Then call the authorization endpoint (which will immediately redirect back), " +
		"exchange the authorization code for an access token at the token endpoint and " +
		"make a GET request to the accounts/payments endpoint displayed.",
	profile = "FAPI1-Advanced-Final",
	configurationFields = {
		"server.jwks",
		"directory.keystore"
	}
)

public class FAPI1AdvancedFinalBrazilClientDCRHappyPathTest extends AbstractFAPI1AdvancedFinalClientTest {

	@Override
	protected void addCustomValuesToIdToken(){
		//Do nothing
	}

	@Override
	protected void configureClients() {
		//do nothing, the client needs to register first
	}
/*
	//FIXME remove later. register must be over mtls
	@Override
	public Object handleHttp(String path, HttpServletRequest req, HttpServletResponse res, HttpSession session, JsonObject requestParts) {
		if(path.equals("register")) {
			setStatus(Status.RUNNING);

			String requestId = "incoming_request_" + RandomStringUtils.randomAlphanumeric(37);

			env.putObject(requestId, requestParts);

			call(exec().mapKey("client_request", requestId));

			callAndContinueOnFailure(EnsureIncomingTls12WithSecureCipherOrTls13.class, Condition.ConditionResult.FAILURE, "FAPI1-BASE-7.1", "FAPI1-ADV-8.5-1");

			call(exec().unmapKey("client_request"));

			setStatus(Status.WAITING);

			return handleRegistrationEndpointRequest(requestId);
		} else {
			return super.handleHttp(path, req, res, session, requestParts);
		}
	}
*/
	@Override
	public Object handleHttpMtls(String path, HttpServletRequest req, HttpServletResponse res, HttpSession session, JsonObject requestParts) {
		if(path.equals("register")) {
			setStatus(Status.RUNNING);

			String requestId = "incoming_request_" + RandomStringUtils.randomAlphanumeric(37);

			env.putObject(requestId, requestParts);

			call(exec().mapKey("client_request", requestId));

			callAndContinueOnFailure(EnsureIncomingTls12WithSecureCipherOrTls13.class, Condition.ConditionResult.FAILURE, "FAPI1-BASE-7.1", "FAPI1-ADV-8.5-1");

			call(exec().unmapKey("client_request"));

			setStatus(Status.WAITING);

			return handleRegistrationEndpointRequest(requestId);
		} else {
			return super.handleHttpMtls(path, req, res, session, requestParts);
		}
	}

	protected Object handleRegistrationEndpointRequest(String requestId) {
		setStatus(Status.RUNNING);
		call(exec().startBlock("Registration endpoint").mapKey("incoming_request", requestId));

		call(exec().mapKey("token_endpoint_request", requestId));
		callAndContinueOnFailure(ExtractClientCertificateFromTokenEndpointRequestHeaders.class);
		callAndContinueOnFailure(CheckForClientCertificate.class, Condition.ConditionResult.FAILURE, "FAPI1-ADV-5.2.2-5");
		//TODO shall reject dynamic client registration requests not performed over a connection secured with mutual tls
		// using certificates issued by Brazil ICP (production) or the Directory of Participants (sandbox);
		call(exec().unmapKey("token_endpoint_request"));

		callAndStopOnFailure(OIDCCExtractDynamicRegistrationRequest.class);
		callAndStopOnFailure(FAPIBrazilExtractSSAFromDynamicRegistrationRequest.class);
		callAndStopOnFailure(FAPIBrazilFetchDirectorySSAJwks.class);
		callAndStopOnFailure(FAPIBrazilValidateSSASignature.class);
		callAndStopOnFailure(FAPIBrazilExtractSoftwareStatement.class);

		env.mapKey("client", "dynamic_registration_request");
		validateClientRegistrationMetadata();
		env.unmapKey("client");

		validateClientRegistrationBrazilSpecificChecks();

		JsonObject registeredClient = registerClient().deepCopy();

		//Note that we don't want to include the jwks in the returned response, that's why we have the deepCopy above
		callAndStopOnFailure(FetchClientKeys.class);
		validateClientJwks(false);

		call(exec().unmapKey("incoming_request").endBlock());

		setStatus(Status.WAITING);
		return new ResponseEntity<Object>(registeredClient, HttpStatus.CREATED);
	}

	protected void validateClientRegistrationBrazilSpecificChecks() {
		//BrazilOBDCR- 7.1-3 shall validate that the software_statement was issued (iat) not more than 5 minutes prior to the request being received
		callAndContinueOnFailure(FAPIBrazilValidateSoftwareStatementIat.class, Condition.ConditionResult.FAILURE,"BrazilOBDCR-7.1-3");
		//BrazilOBDCR- 7.1-4 shall validate that a jwks (key set by value) was not included;
		callAndContinueOnFailure(FAPIBrazilEnsureRegistrationRequestDoesNotIncludeJwks.class, Condition.ConditionResult.FAILURE,"BrazilOBDCR-7.1-4");
		//BrazilOBDCR- 7.1-5 shall require and validate that the jwks_uri matches the software_jwks_uri provided in the software statement;
		callAndContinueOnFailure(FAPIBrazilEnsureJwksUriMatchesSoftwareJwksUri.class, Condition.ConditionResult.FAILURE,"BrazilOBDCR-7.1-5");
		//BrazilOBDCR- 7.1-6 shall require and validate that redirect_uris match or contain a sub set of softwareredirecturis provided in the software statement;
		callAndContinueOnFailure(FAPIBrazilEnsureRedirectUrisMatchSoftwareRedirectUris.class, Condition.ConditionResult.FAILURE,"BrazilOBDCR-7.1-6");
		//BrazilOBDCR- 7.1-7 shall require and validate that all client authentication mechanism adhere to the requirements defined in Financial-grade API Security Profile 1.0 - Part 1: Advanced;
		callAndContinueOnFailure(FAPIBrazilValidateClientAuthenticationMethods.class, Condition.ConditionResult.FAILURE, "BrazilOBDCR-7.1-7");
		//BrazilOBDCR- 7.1-8 shall require encrypted request objects as required by the Brasil Open Banking Security Profile;
		if(authRequestMethod!= FAPIAuthRequestMethod.PUSHED) {
			callAndContinueOnFailure(FAPIBrazilValidateRequestObjectEncryption.class, Condition.ConditionResult.FAILURE,"BrazilOBDCR-7.1-8");
		}

		//TODO how do you validate this during registration? registration request does not contain scopes?
		//BrazilOBDCR- 7.1-9 shall require encrypted request objects as required by the Brasil Open Banking Security Profile;
		//software_statement_roles -> "role": "DADOS",

		//BrazilOBDCR- 7.1-10 should where possible validate client asserted metadata against metadata provided in the software_statement;
		callAndContinueOnFailure(FAPIBrazilEnsureClientMetadataMatchSoftwareStatement.class, Condition.ConditionResult.FAILURE, "BrazilOBDCR-7.1-10");

		//BrazilOBDCR- 7.1-11 shall accept all x.500 AttributeType name strings defined in the Distinguished Name of the
		// x.509 Certificate Profiles defined in Open Banking Brasil x.509 Certificate Standards;

		//BrazilOBDCR- 7.1-12 if supporting tls_client_auth client authentication mechanism as defined in RFC8705 shall
		// only accept tls_client_auth_subject_dn as an indication of the certificate subject value as defined in clause 2.1.2 RFC8705;
	}

	protected void validateClientRegistrationMetadata(){
		//check response type - grant type consistency
		callAndContinueOnFailure(ValidateClientGrantTypes.class, Condition.ConditionResult.FAILURE, "OIDCR-2");
		//basic checks like fragments, https etc
		callAndContinueOnFailure(OIDCCValidateClientRedirectUris.class, Condition.ConditionResult.FAILURE, "OIDCR-2");

		//check if logo is image
		callAndContinueOnFailure(ValidateClientLogoUris.class, Condition.ConditionResult.FAILURE,"OIDCR-2");
		//check if uri is valid
		callAndContinueOnFailure(ValidateClientUris.class, Condition.ConditionResult.FAILURE,"OIDCR-2");
		//check if uri is valid
		callAndContinueOnFailure(ValidateClientPolicyUris.class, Condition.ConditionResult.FAILURE,"OIDCR-2");
		//check if uri is valid
		callAndContinueOnFailure(ValidateClientTosUris.class, Condition.ConditionResult.FAILURE,"OIDCR-2");

		callAndContinueOnFailure(ValidateClientSubjectType.class, Condition.ConditionResult.FAILURE,"OIDCR-2");

		skipIfElementMissing("client", "id_token_signed_response_alg", Condition.ConditionResult.INFO,
			FAPIBrazilValidateIdTokenSignedResponseAlg.class, Condition.ConditionResult.FAILURE, "BrazilOB-6.2");

		callAndContinueOnFailure(EnsureIdTokenEncryptedResponseAlgIsSetIfEncIsSet.class, Condition.ConditionResult.FAILURE,"OIDCR-2");

		//userinfo
		skipIfElementMissing("client", "userinfo_signed_response_alg", Condition.ConditionResult.INFO,
			ValidateUserinfoSignedResponseAlg.class, Condition.ConditionResult.FAILURE, "OIDCR-2");
		skipIfElementMissing("client", "userinfo_signed_response_alg", Condition.ConditionResult.INFO,
			FAPIBrazilValidateUserinfoSignedResponseAlg.class, Condition.ConditionResult.FAILURE, "BrazilOB-6.2");

		callAndContinueOnFailure(EnsureUserinfoEncryptedResponseAlgIsSetIfEncIsSet.class, Condition.ConditionResult.FAILURE,"OIDCR-2");

		//request object
		skipIfElementMissing("client", "request_object_signing_alg", Condition.ConditionResult.INFO,
			FAPIBrazilValidateRequestObjectSigningAlg.class, Condition.ConditionResult.FAILURE, "OIDCR-2");

		callAndContinueOnFailure(EnsureRequestObjectEncryptionAlgIsSetIfEncIsSet.class, Condition.ConditionResult.FAILURE,"OIDCR-2");


		skipIfElementMissing("client", "token_endpoint_auth_signing_alg", Condition.ConditionResult.INFO,
			FAPIBrazilValidateTokenEndpointAuthSigningAlg.class, Condition.ConditionResult.FAILURE, "OIDCR-2");

		callAndContinueOnFailure(ValidateDefaultMaxAge.class,"OIDCR-2");

		skipIfElementMissing("client", "require_auth_time", Condition.ConditionResult.INFO,
			ValidateRequireAuthTime.class, Condition.ConditionResult.FAILURE, "OIDCR-2");

		skipIfElementMissing("client", "default_acr_values", Condition.ConditionResult.INFO,
			FAPIBrazilValidateDefaultAcrValues.class, Condition.ConditionResult.FAILURE, "OIDCR-2");

		skipIfElementMissing("client", "initiate_login_uri", Condition.ConditionResult.INFO,
			ValidateInitiateLoginUri.class, Condition.ConditionResult.FAILURE, "OIDCR-2");

		//TODO not allow request_uris?
		/*
		skipIfElementMissing("client", "request_uris", Condition.ConditionResult.INFO,
			ValidateRequestUris.class, Condition.ConditionResult.FAILURE, "OIDCR-2");
		 */
	}

	protected JsonObject registerClient() {
		callAndStopOnFailure(FAPIBrazilRegisterClient.class);
		JsonObject client = env.getObject("client");
		return client;
	}

	@Override
	protected void validateRedirectUriInRequestObject() {
		callAndContinueOnFailure(EnsureRedirectUriInRequestObjectMatchesOneOfClientRedirectUris.class, Condition.ConditionResult.FAILURE);
	}

	@Override
	protected void validateRedirectUriForAuthorizationCodeGrantType() {
		callAndStopOnFailure(ValidateRedirectUriForTokenEndpointRequest.class);
	}
}
