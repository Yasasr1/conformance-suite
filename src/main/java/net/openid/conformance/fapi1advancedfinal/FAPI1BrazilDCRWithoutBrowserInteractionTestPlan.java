package net.openid.conformance.fapi1advancedfinal;

import net.openid.conformance.plan.PublishTestPlan;
import net.openid.conformance.plan.TestPlan;
import net.openid.conformance.variant.FAPI1FinalOPProfile;
import net.openid.conformance.variant.VariantSelection;

import java.util.List;


@PublishTestPlan(
	testPlanName = "brazil-dcr-without-browser-interaction",
	displayName = "Brazil DCR Test without Browser Interaction",
	profile = TestPlan.ProfileNames.optest
)
public class FAPI1BrazilDCRWithoutBrowserInteractionTestPlan implements TestPlan {

	public static List<ModuleListEntry> testModulesWithVariants() {

		return List.of(
			new ModuleListEntry(
				List.of(
					FAPI1AdvancedFinalBrazilDCRHappyFlowNoAuth.class, //TODO Fields
					FAPI1AdvancedFinalBrazilDCRHappyFlowVariantNoAuth.class, //TODO Fields
					FAPI1AdvancedFinalBrazilDCRHappyFlowVariant2NoAuth.class, //TODO Fields
					FAPI1AdvancedFinalBrazilDCRClientDeletion.class,
					FAPI1AdvancedFinalBrazilDCRInvalidRegistrationAccessToken.class,
					FAPI1AdvancedFinalBrazilDCRInvalidSoftwareStatementSignature.class,
					FAPI1AdvancedFinalBrazilDCRNoSoftwareStatement.class,
					FAPI1AdvancedFinalBrazilDCRNoMTLS.class,
					FAPI1AdvancedFinalBrazilDCRBadMTLS.class,
					FAPI1AdvancedFinalBrazilDCRUpdateClientConfigNoAuth.class, //TODO Fields, Confirm Changes
					FAPI1AdvancedFinalBrazilDCRUpdateClientConfigBadJwksUri.class,
					FAPI1AdvancedFinalBrazilDCRUpdateClientConfigInvalidJwksByValue.class,
					FAPI1AdvancedFinalBrazilDCRUpdateClientConfigInvalidRedirectUri.class, //TODO Ask Erick
					FAPI1AdvancedFinalBrazilDCRNoRedirectUri.class,
					FAPI1AdvancedFinalBrazilDCRInvalidRedirectUri.class,
					FAPI1AdvancedFinalBrazilDCRInvalidJwksUri.class,
					FAPI1AdvancedFinalBrazilDCRInvalidJwksByValue.class
				),
				List.of(new Variant(FAPI1FinalOPProfile.class, "openbanking_brazil"))
			)
		);

	}
	public static String certificationProfileName(VariantSelection variant) {
		return "BR-OB Adv. OP DCR";
	}
}
