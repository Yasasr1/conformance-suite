package net.openid.conformance.openbanking_brasil.registrationData;

import com.google.common.collect.Sets;
import com.google.gson.JsonObject;
import net.openid.conformance.condition.PreEnvironment;
import net.openid.conformance.condition.client.AbstractJsonAssertingCondition;
import net.openid.conformance.logging.ApiName;
import net.openid.conformance.testmodule.Environment;
import net.openid.conformance.util.fields.*;

import java.util.Set;

/**
 * This is validator for API-Dados Cadastrais | Identificacao pessoa jurídica
 * See <a href="https://openbanking-brasil.github.io/areadesenvolvedor/#identificacao-pessoa-juridica">Identificação Pessoa Jurídica </a>
 **/
@ApiName("Legal Identity")
public class LegalEntityIdentificationValidator extends AbstractJsonAssertingCondition {

	@Override
	@PreEnvironment(strings = "resource_endpoint_response")
	public Environment evaluate(Environment environment) {
		JsonObject body = bodyFrom(environment);
		assertHasField(body, ROOT_PATH);
		assertJsonArrays(body, ROOT_PATH, this::assertData);
		return environment;
	}

	private void assertData(JsonObject body) {
		assertDateTimeField(body, new DatetimeField("updateDateTime"));

		assertStringField(body,
			new StringField
				.Builder("businessId")
//				.setPattern("\\w*\\W*")
				.setMaxLength(100)
				.build());

		assertStringField(body,
			new StringField
				.Builder("brandName")
//				.setPattern("\\w*\\W*")
				.setMaxLength(80)
				.build());

		assertStringField(body,
			new StringField
				.Builder("companyName")
//				.setPattern("\\w*\\W*")
				.setMaxLength(70)
				.build());

		assertStringField(body,
			new StringField
				.Builder("tradeName")
//				.setPattern("\\w*\\W*")
				.setMaxLength(70)
				.build());

		assertDateTimeField(body, new DatetimeField("incorporationDate"));

		assertStringField(body,
			new StringField
				.Builder("cnpjNumber")
				.setPattern("\\d{14}|^NA$")
				.setMaxLength(14)
				.build());

		//TODO need to check impl. for array
		assertStringArrayField(body,
			new StringArrayField
				.Builder("companyCnpjNumber")
				.setPattern("\\d{14}|^NA$")
				.setMaxLength(14)
				.build());

		assertOptionalJsonArrays(body, "otherDocuments", this::assertOtherDocuments);

		assertHasField(body, "parties");
		assertJsonArrays(body, "parties", this::assertParties);

		assertContacts(body);
	}

	private void assertOtherDocuments(JsonObject body) {
		assertStringField(body,
			new StringField
				.Builder("type")
				.setPattern("\\w*\\W*")
				.setMaxLength(20)
				.setFieldOptional()
				.build());

		assertStringField(body,
			new StringField
				.Builder("number")
				.setPattern("\\w*\\W*")
				.setMaxLength(20)
				.build());

		assertStringField(body,
			new StringField
				.Builder("country")
				.setPattern("^(\\w{3}){1}$|^NA$")
				.setMaxLength(3)
				.build());

		assertStringField(body,
			new StringField
				.Builder("expirationDate")
				.setPattern("(\\d{4})-(1[0-2]|0?[1-9])-(3[01]|[12][0-9]|0?[1-9])$|^NA$")
				.setMaxLength(10)
				.build());
	}

	private void assertParties(JsonObject body) {
		Set<String> personTypes = Sets.newHashSet("PESSOA_NATURAL", "PESSOA_JURIDICA");

		assertStringField(body,
			new StringField
				.Builder("personType")
				.setEnums(personTypes)
				.build());

		assertStringField(body,
			new StringField
				.Builder("type")
				.setEnums(Sets.newHashSet("SOCIO", "ADMINISTRADOR"))
				.build());

		assertStringField(body,
			new StringField
				.Builder("civilName")
				.setMaxLength(70)
//				.setPattern("\\w*\\W*")
				.build());

		assertStringField(body,
			new StringField
				.Builder("socialName")
				.setMaxLength(70)
//				.setPattern("\\w*\\W*")
				.build());

		assertStringField(body,
			new StringField
				.Builder("companyName")
				.setMaxLength(70)
				//.setPattern("\\w*\\W*")
				.build());

		assertStringField(body,
			new StringField
				.Builder("tradeName")
				.setMaxLength(70)
				//.setPattern("\\w*\\W*")
				.setFieldOptional()
				.build());

		assertDateTimeField(body, new DatetimeField("startDate"));

		assertStringField(body,
			new StringField
				.Builder("shareholding")
				.setMaxLength(4)
				.setPattern("^((\\d{1,9}\\.\\d{2}){1}|NA)$")
				.build());

		assertStringField(body,
			new StringField
				.Builder("documentType")
				.setEnums(Sets.newHashSet("CPF", "PASSAPORTE", "OUTRO_DOCUMENTO_VIAGEM", "CNPJ"))
				.build());

		assertStringField(body,
			new StringField
				.Builder("documentNumber")
				.setMaxLength(20)
				//.setPattern("\\w*\\W*")
				.build());

		assertStringField(body,
			new StringField
				.Builder("documentAdditionalInfo")
				.setMaxLength(100)
				//.setPattern("\\w*\\W*")
				.setFieldOptional()
				.build());

		assertStringField(body,
			new StringField
				.Builder("documentCountry")
				.setMaxLength(3)
				.build());

		assertStringField(body,
			new StringField
				.Builder("documentExpirationDate")
				.setMaxLength(10)
				.setPattern("^(\\d{4})-(1[0-2]|0?[1-9])-(3[01]|[12][0-9]|0?[1-9])|^NA$")
				.build());

		assertStringField(body,
			new StringField
				.Builder("documentIssueDate")
				.setMaxLength(10)
				.setPattern("^(\\d{4})-(1[0-2]|0?[1-9])-(3[01]|[12][0-9]|0?[1-9])$")
				.setFieldOptional()
				.build());
	}

	private void assertContacts(JsonObject body) {
		JsonObject contacts = findByPath(body, "contacts").getAsJsonObject();
		assertPostalAddresses(contacts);
		assertPhones(contacts);
		assertEmails(contacts);
	}

	private void assertEmails(JsonObject body) {
		assertHasField(body, "emails");
		assertJsonArrays(body, "emails", this::assertInnerEmails);
	}

	private void assertInnerEmails(JsonObject body) {
		assertBooleanField(body, new BooleanField.Builder("isMain").build());

		assertStringField(body,
			new StringField
				.Builder("email")
				.setMaxLength(320)
				//.setPattern("\\w*\\W*")
				.build());
	}

	private void assertPhones(JsonObject body) {
		assertHasField(body, "phones");
		assertJsonArrays(body, "phones", this::assertInnerPhones);
	}

	private void assertInnerPhones(JsonObject body) {
		final Set<String> areaCodes = Set.of("11", "12", "13", "14", "15", "16", "17",
			"18", "19", "21", "22", "24", "27", "28", "31", "32", "33", "34", "35", "37", "38",
			"41", "42", "43", "44", "45", "46", "47", "48", "49", "51", "53", "54", "55",
			"61", "62", "63", "64", "65", "66", "67", "68", "69", "71", "73", "74", "75",
			"77", "79", "81", "82", "83", "84", "85", "86", "87", "88", "89", "91", "92",
			"93", "94", "95", "96", "97", "98", "99", "NA");

		assertBooleanField(body, new BooleanField.Builder("isMain").build());
		assertStringField(body,
			new StringField
				.Builder("type")
				.setMaxLength(5)
				.setEnums(Sets.newHashSet("FIXO", "MOVEL", "OUTRO"))
				.build());

		assertStringField(body,
			new StringField
				.Builder("additionalInfo")
				.setMaxLength(70)
				//.setPattern("\\w*\\W*")
				.setFieldOptional()
				.build());

		assertStringField(body,
			new StringField
				.Builder("countryCallingCode")
				.setPattern("^\\d{2,4}$|^NA$")
				.setMaxLength(4)
				.build());

		assertStringField(body,
			new StringField
				.Builder("areaCode")
				.setMaxLength(2)
				.setEnums(areaCodes)
				.build());

		assertStringField(body,
			new StringField
				.Builder("number")
				.setMaxLength(11)
				.setPattern("^([0-9]{8,11})|^NA$")
				.build());

		assertStringField(body,
			new StringField
				.Builder("phoneExtension")
				.setMaxLength(5)
				.setPattern("^\\d{1,5}$|^NA$")
				.build());
	}

	private void assertPostalAddresses(JsonObject body) {
		assertHasField(body, "postalAddresses");
		assertJsonArrays(body, "postalAddresses", this::assertInnerPostalAddresses);
	}

	private void assertGeographicCoordinates(JsonObject body) {
		assertLatitude(body,
			new DoubleField
				.Builder("latitude")
				.setMaxLength(13)
				.setPattern("^-?\\d{1,2}\\.\\d{1,9}$")
				.setFieldOptional()
				.build());

		assertLongitude(body,
			new DoubleField
				.Builder("longitude")
				.setMaxLength(13)
				.setPattern("^-?\\d{1,3}\\.\\d{1,8}$")
				.setFieldOptional()
				.build());
	}

	private void assertInnerPostalAddresses(JsonObject body) {
		final Set<String> countrySubDivisions = Set.of("AC", "AL", "AP", "AM",
			"BA", "CE", "DF", "ES", "GO", "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ",
			"RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO", "NA");

		assertBooleanField(body, new BooleanField.Builder("isMain").build());

		assertStringField(body,
			new StringField
				.Builder("address")
				.setMaxLength(150)
//				.setPattern("\\w*\\W*|^NA$")
				.build());

		assertStringField(body,
			new StringField
				.Builder("additionalInfo")
				.setMaxLength(30)
				//.setPattern("\\w*\\W*")
				.setFieldOptional()
				.build());

		assertStringField(body,
			new StringField
				.Builder("districtName")
				.setMaxLength(50)
				//.setPattern("\\w*\\W*|^NA$")
				.build());

		assertStringField(body,
			new StringField
				.Builder("townName")
				.setMaxLength(50)
				//.setPattern("\\w*\\W*|^NA$")
				.build());

		assertStringField(body,
			new StringField
				.Builder("ibgeTownCode")
				.setMaxLength(7)
				.setPattern("\\d{7}$")
				.setFieldOptional()
				.build());

		assertStringField(body,
			new StringField
				.Builder("countrySubDivision")
				.setEnums(countrySubDivisions)
				.build());

		assertStringField(body,
			new StringField
				.Builder("postCode")
				.setMaxLength(8)
				.setPattern("\\d{8}|^NA$")
				.build());

		assertStringField(body,
			new StringField
				.Builder("country")
				.setMaxLength(80)
				//.setPattern("\\w*\\W*|^NA$")
				.build());

		assertStringField(body,
			new StringField
				.Builder("countryCode")
				.setMaxLength(3)
				.setFieldOptional()
				.build());

		assertGeographicCoordinates(body);
	}
}