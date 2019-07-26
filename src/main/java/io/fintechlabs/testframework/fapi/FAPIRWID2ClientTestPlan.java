package io.fintechlabs.testframework.fapi;

import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKey;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyIatIsWeekInPast;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidAlternateAlg;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidAud;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidCHash;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidExpiredExp;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidIss;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingAud;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingExp;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingIss;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingNonce;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingSHash;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidNonce;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidNullAlg;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidOpenBankingIntentId;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidSHash;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidSecondaryAud;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidSignature;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyNoAtHash;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithMTLSHolderOfKeyValidAudAsArray;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKey;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyIatIsWeekInPast;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidAlternateAlg;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidAud;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidCHash;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidExpiredExp;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidIss;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingAud;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingExp;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingIss;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingNonce;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingSHash;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidNonce;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidNullAlg;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidOpenBankingIntentId;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSHash;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSecondaryAud;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSignature;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyNoAtHash;
import io.fintechlabs.testframework.openbanking.FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyValidAudAsArray;
import io.fintechlabs.testframework.plan.PublishTestPlan;
import io.fintechlabs.testframework.plan.TestPlan;

@PublishTestPlan (
	testPlanName = "fapi-rw-id2-client-test-plan",
	displayName = "FAPI-RW-ID2: Relying Party (client test)",
	profile = "FAPI-RW-ID2-Relying-Party-Client-Test",
	testModules = {
		FAPIRWID2ClientTestWithMTLSHolderOfKey.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidSHash.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidCHash.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidNonce.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidIss.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidAud.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidSecondaryAud.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidSignature.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidNullAlg.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidAlternateAlg.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidExpiredExp.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidMissingExp.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyIatIsWeekInPast.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidMissingAud.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidMissingIss.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidMissingNonce.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyInvalidMissingSHash.class,
		FAPIRWID2ClientTestWithMTLSHolderOfKeyValidAudAsArray.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKey.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSHash.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidCHash.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidNonce.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidIss.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidAud.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSecondaryAud.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSignature.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidNullAlg.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidAlternateAlg.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingExp.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidExpiredExp.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyIatIsWeekInPast.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingAud.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingIss.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingNonce.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingSHash.class,
		FAPIRWID2ClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyValidAudAsArray.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKey.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyNoAtHash.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidSHash.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidCHash.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidNonce.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidIss.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidAud.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidSecondaryAud.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidOpenBankingIntentId.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidSignature.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidNullAlg.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidAlternateAlg.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingExp.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidExpiredExp.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyIatIsWeekInPast.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingAud.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingIss.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingNonce.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyInvalidMissingSHash.class,
		FAPIRWID2OBClientTestWithMTLSHolderOfKeyValidAudAsArray.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKey.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyNoAtHash.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSHash.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidCHash.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidNonce.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidIss.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidAud.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSecondaryAud.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidOpenBankingIntentId.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidSignature.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidNullAlg.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidAlternateAlg.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingExp.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidExpiredExp.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyIatIsWeekInPast.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingAud.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingIss.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingNonce.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyInvalidMissingSHash.class,
		FAPIRWID2OBClientTestWithPrivateKeyJWTAndMTLSHolderOfKeyValidAudAsArray.class
	},
	variants = {
		FAPIRWID2ClientTest.variant_mtls,
		FAPIRWID2ClientTest.variant_privatekeyjwt,
		FAPIRWID2ClientTest.variant_openbankinguk_mtls,
		FAPIRWID2ClientTest.variant_openbankinguk_privatekeyjwt
	}
)
public class FAPIRWID2ClientTestPlan implements TestPlan {

}