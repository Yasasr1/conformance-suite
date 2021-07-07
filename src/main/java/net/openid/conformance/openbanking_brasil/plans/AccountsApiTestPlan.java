package net.openid.conformance.openbanking_brasil.plans;

import net.openid.conformance.openbanking_brasil.OBBProfile;
import net.openid.conformance.openbanking_brasil.testmodules.AccountApiTestModule;
import net.openid.conformance.openbanking_brasil.testmodules.AccountApiWrongPermissionsTestModule2;
import net.openid.conformance.openbanking_brasil.testmodules.AccountsApiWrongPermissionsTestModule;
import net.openid.conformance.plan.PublishTestPlan;
import net.openid.conformance.plan.TestPlan;

@PublishTestPlan(
	testPlanName = "Account api test",
	profile = OBBProfile.OBB_PROFILE,
	displayName = PlanNames.ACCOUNT_API_NAME,
	summary = "Structural and logical tests for OpenBanking Brasil-conformant Account API",
	testModules = {
		AccountApiTestModule.class,
		AccountsApiWrongPermissionsTestModule.class,
		AccountApiWrongPermissionsTestModule2.class
	})
public class AccountsApiTestPlan implements TestPlan {
}
