package net.openid.conformance.openbanking_brasil.plans;

import net.openid.conformance.openbanking_brasil.OBBProfile;
import net.openid.conformance.openbanking_brasil.testmodules.creditOperations.discounted.testmodule.CreditOperationsDiscountedApiWrongPermissionsTestModule;
import net.openid.conformance.openbanking_brasil.testmodules.creditOperations.discounted.testmodule.CreditOperationsDiscountedCreditRightsApiTestModule;
import net.openid.conformance.plan.PublishTestPlan;
import net.openid.conformance.plan.TestPlan;

@PublishTestPlan(
	testPlanName = "Credit operations discounted credit rights api test",
	profile = OBBProfile.OBB_PROFILE,
	displayName = PlanNames.CREDIT_OPERATIONS_DISCOUNTED_CREDIT_RIGHTS_API_PLAN_NAME,
	summary = "Structural and logical tests for OpenBanking Brasil-conformant Discounted Credit Rights API",
	testModules = {
		CreditOperationsDiscountedCreditRightsApiTestModule.class,
		CreditOperationsDiscountedApiWrongPermissionsTestModule.class
	})
public class CreditOperationsDiscountedCreditRightsApiTestPlan implements TestPlan {
}