package net.openid.conformance.openbanking_brasil.testmodules;

import net.openid.conformance.condition.Condition;
import net.openid.conformance.openbanking_brasil.testmodules.support.SetDirectoryInfo;
import net.openid.conformance.openbanking_brasil.testmodules.support.MapDirectoryValues;
import net.openid.conformance.openbanking_brasil.testmodules.support.UnmapDirectoryValues;
import net.openid.conformance.condition.client.ExtractDirectoryConfiguration;
import net.openid.conformance.condition.client.FAPIBrazilCheckDirectoryDiscoveryUrl;
import net.openid.conformance.condition.client.FAPIBrazilCheckDirectoryApiBase;
import net.openid.conformance.condition.client.GetDynamicServerConfiguration;
import net.openid.conformance.condition.client.AddMTLSEndpointAliasesToEnvironment;
import net.openid.conformance.condition.client.CreateTokenEndpointRequestForClientCredentialsGrant;
import net.openid.conformance.condition.client.SetDirectorySoftwareScopeOnTokenEndpointRequest;
import net.openid.conformance.condition.client.AddClientIdToTokenEndpointRequest;
import net.openid.conformance.condition.client.CallTokenEndpoint;
import net.openid.conformance.condition.client.CheckIfTokenEndpointResponseError;
import net.openid.conformance.condition.client.CheckForAccessTokenValue;
import net.openid.conformance.condition.client.ExtractAccessTokenFromTokenResponse;
import net.openid.conformance.condition.client.FAPIBrazilExtractClientMTLSCertificateSubject;
import net.openid.conformance.condition.client.FAPIBrazilCallDirectorySoftwareStatementEndpointWithBearerToken;
import net.openid.conformance.condition.client.ValidateMTLSCertificatesHeader;
import net.openid.conformance.condition.client.ExtractMTLSCertificatesFromConfiguration;
import net.openid.conformance.condition.client.ExtractJWKSDirectFromClientConfiguration;
import net.openid.conformance.condition.common.CheckDistinctKeyIdValueInClientJWKs;
import net.openid.conformance.variant.ClientAuthType;
import net.openid.conformance.openbanking_brasil.OBBProfile;
import net.openid.conformance.testmodule.PublishTestModule;

@PublishTestModule(
	testName = "preflight-cert-check-test",
	displayName = "",
	summary = "",
	profile = OBBProfile.OBB_PROFILE,
	configurationFields = {
		"server.discoveryUrl",
		"client.client_id",
		"client.jwks",
		"mtls.key",
		"mtls.cert",
		"mtls.ca",
		"resource.consentUrl",
		"resource.brazilCpf",
        "directory.client_id"
	}
)

public class PreFlightCertCheckModule extends AbstractClientCredentialsGrantFunctionalTestModule {

    @Override
    protected void runTests() {
        runInBlock("Pre-flight MTLS Cert Checks", () -> {
            callAndContinueOnFailure(ValidateMTLSCertificatesHeader.class, Condition.ConditionResult.WARNING);
		    callAndContinueOnFailure(ExtractMTLSCertificatesFromConfiguration.class, Condition.ConditionResult.FAILURE);

            // normally our DCR tests create a key on the fly to use, but in this case the key has to be registered
            // manually with the central directory so we must use user supplied keys
            callAndStopOnFailure(ExtractJWKSDirectFromClientConfiguration.class);

            callAndContinueOnFailure(CheckDistinctKeyIdValueInClientJWKs.class, Condition.ConditionResult.FAILURE, "RFC7517-4.5");
        });

        runInBlock("Pre-flight Get an SSA", () -> {

            callAndStopOnFailure(SetDirectoryInfo.class);
            callAndStopOnFailure(ExtractDirectoryConfiguration.class);

		    callAndContinueOnFailure(FAPIBrazilCheckDirectoryDiscoveryUrl.class, Condition.ConditionResult.FAILURE, "BrazilOBDCR-7.1-1");

		    callAndContinueOnFailure(FAPIBrazilCheckDirectoryApiBase.class, Condition.ConditionResult.FAILURE, "BrazilOBDCR-7.1-1");

            callAndStopOnFailure(MapDirectoryValues.class);

            callAndStopOnFailure(GetDynamicServerConfiguration.class);

            // this overwrites the non-directory values; we will have to replace them below
            callAndContinueOnFailure(AddMTLSEndpointAliasesToEnvironment.class, Condition.ConditionResult.FAILURE, "RFC8705-5");

            callAndStopOnFailure(CreateTokenEndpointRequestForClientCredentialsGrant.class);

            callAndStopOnFailure(SetDirectorySoftwareScopeOnTokenEndpointRequest.class);

            // MTLS client auth
            callAndStopOnFailure(AddClientIdToTokenEndpointRequest.class);

            callAndStopOnFailure(CallTokenEndpoint.class);

            callAndStopOnFailure(CheckIfTokenEndpointResponseError.class);

            // map access token too?
            callAndStopOnFailure(CheckForAccessTokenValue.class);

            callAndStopOnFailure(ExtractAccessTokenFromTokenResponse.class);

            callAndStopOnFailure(UnmapDirectoryValues.class);

            // restore MTLS aliases to the values for the server being tested
            callAndContinueOnFailure(AddMTLSEndpointAliasesToEnvironment.class, Condition.ConditionResult.FAILURE, "RFC8705-5");

            callAndStopOnFailure(FAPIBrazilExtractClientMTLSCertificateSubject.class);

            // use access token to get ssa
            // https://matls-api.sandbox.directory.openbankingbrasil.org.br/organisations/${ORGID}/softwarestatements/${SSID}/assertion
            callAndStopOnFailure(FAPIBrazilCallDirectorySoftwareStatementEndpointWithBearerToken.class);
        });
    }    
}