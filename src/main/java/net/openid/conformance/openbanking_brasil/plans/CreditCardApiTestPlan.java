package net.openid.conformance.openbanking_brasil.plans;


import net.openid.conformance.openbanking_brasil.OBBProfile;
import net.openid.conformance.openbanking_brasil.testmodules.CreditCardApiTestModule;
import net.openid.conformance.plan.PublishTestPlan;
import net.openid.conformance.plan.TestPlan;

@PublishTestPlan(
	testPlanName = "Credit card api test",
	profile = OBBProfile.OBB_PROFILE,
	displayName = PlanNames.CREDIT_CARDS_API_PLAN_NAME,
	summary = "Structural and logical tests for OpenBanking Brasil-conformant Credit Cards API",
	testModules = {
		CreditCardApiTestModule.class
	})
public class CreditCardApiTestPlan implements TestPlan {
}