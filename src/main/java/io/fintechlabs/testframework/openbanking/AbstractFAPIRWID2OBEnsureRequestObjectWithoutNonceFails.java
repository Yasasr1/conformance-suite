package io.fintechlabs.testframework.openbanking;

import io.fintechlabs.testframework.condition.Condition;
import io.fintechlabs.testframework.condition.client.AddAccountRequestIdToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.OBValidateIdTokenIntentId;
import io.fintechlabs.testframework.condition.client.OpenBankingUkAddMultipleAcrClaimsToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.condition.client.OpenBankingUkAddScaAcrClaimToAuthorizationEndpointRequest;
import io.fintechlabs.testframework.fapi.AbstractFAPIRWID2EnsureRequestObjectWithoutNonceFails;

public abstract class AbstractFAPIRWID2OBEnsureRequestObjectWithoutNonceFails extends AbstractFAPIRWID2EnsureRequestObjectWithoutNonceFails {

	@Override
	protected void performProfileIdTokenValidation() {
		callAndContinueOnFailure(OBValidateIdTokenIntentId.class, Condition.ConditionResult.FAILURE, "OIDCC-2");

	}

	@Override
	protected void performProfileAuthorizationEndpointSetup() {
		callAndStopOnFailure(AddAccountRequestIdToAuthorizationEndpointRequest.class);

		callAndStopOnFailure(OpenBankingUkAddMultipleAcrClaimsToAuthorizationEndpointRequest.class);
	}
}
