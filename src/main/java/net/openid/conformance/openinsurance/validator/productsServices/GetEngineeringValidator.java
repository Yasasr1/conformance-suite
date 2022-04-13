package net.openid.conformance.openinsurance.validator.productsServices;

import com.google.common.collect.Sets;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.openid.conformance.condition.client.jsonAsserting.AbstractJsonAssertingCondition;
import net.openid.conformance.logging.ApiName;
import net.openid.conformance.openbanking_brasil.productsNServices.ProductNServicesCommonFields;
import net.openid.conformance.openinsurance.validator.OpenInsuranceLinksAndMetaValidator;
import net.openid.conformance.testmodule.Environment;
import net.openid.conformance.util.field.*;

import java.util.Set;

/**
 * Api Source: swagger/openinsurance/productsServices/engineering.yaml
 * Api endpoint: /engineering/
 * Api version: 1.0.0
 * Git hash: 18b96a6de31ee788c0f2f06c609bcb6adcc926b3
 */

@ApiName("ProductsServices Engineering")
public class GetEngineeringValidator extends AbstractJsonAssertingCondition {
	private static class Fields extends ProductNServicesCommonFields {
	}

	public static final Set<String> COVERAGE = Sets.newHashSet("OBRAS_CIVIS_CONSTRUCAO_E_INSTALACAO_E_MONTAGEM", "AFRETAMENTOS_DE_AERONAVES", "ARMAZENAGEM_FORA_DO_CANTEIRO_DE_OBRAS_OU_LOCAL_SEGURADO", "DANOS_EM_CONSEQUENCIA_DE_ERRO_DE_PROJETO_RISCO_DO_FABRICANTE", "DESPESAS_COM_DESENTULHO_DO_LOCAL", "DESPESAS_DE_SALVAMENTO_E_CONTENCAO_DE_SINISTROS", "DESPESAS_EXTRAORDINARIAS", "EQUIPAMENTOS_DE_ESCRITORIO_E_INFORMATICA", "EQUIPAMENTOS_MOVEIS_ESTACIONARIOS_UTILIZADOS_NA_OBRA", "FERRAMENTAS_DE_PEQUENO_E_MEDIO_PORTE", "HONORARIOS_DE_PERITO", "INCENDIO_APOS_O_TERMINO_DE_OBRAS_ATE_30_DIAS_EXCETO_PARA_REFORMAS_AMPLIACOES", "MANUTENCAO_AMPLA_ATE_24_MESES", "MANUTENCAO_SIMPLES_ATE_24_MESES", "OBRAS_CONCLUIDAS", "OBRAS_TEMPORARIAS", "OBRAS_INSTALACOES_CONTRATADAS_ACEITAS_E_OU_COLOCADAS_EM_OPERACAO", "PROPRIEDADES_CIRCUNVIZINHAS", "RECOMPOSICAO_DE_DOCUMENTOS", "RESPONSABILIDADE_CIVIL_EMPREGADOR", "STANDS_DE_VENDA", "TRANSPORTE_TERRESTRE", "TUMULTOS_GREVES_E_LOCKOUT", "OUTRAS");
	public static final Set<String> TERM = Sets.newHashSet("ANUAL", "ANUAL_INTERMITENTE", "PLURIANUAL", "PLURIANUAL_INTERMITENTE", "MENSAL", "MENSAL_INTERMITENTE", "DIARIO", "DIARIO_INTERMITENTE", "OUTROS");
	public static final Set<String> TARGET_AUDIENCE = Sets.newHashSet("PESSOA_NATURAL", "PESSOA_JURIDICA");


	@Override
	public Environment evaluate(Environment environment) {
		JsonElement body = bodyFrom(environment);

		assertField(body, new ObjectField
			.Builder("data")
			.setValidator(data -> assertField(data, new ObjectField
				.Builder("brand")
				.setValidator(brand -> {
					assertField(brand, Fields.name().setMaxLength(80).build());
					assertField(brand,
						new ObjectArrayField
							.Builder("companies")
							.setValidator(this::assertCompanies)
							.build());
				})
				.build())).build());
		new OpenInsuranceLinksAndMetaValidator(this).assertMetaAndLinks(body);
		logFinalStatus();
		return environment;
	}

	private void assertCompanies(JsonObject companies) {
		assertField(companies, Fields.name().setMaxLength(80).build());
		assertField(companies, Fields.cnpjNumber().setMaxLength(14).build());

		assertField(companies,
			new ObjectArrayField
				.Builder("products")
				.setValidator(this::assertProducts)
				.build());

	}

	private void assertProducts(JsonObject products) {
		assertField(products, Fields.name().setMaxLength(80).build());
		assertField(products, Fields.code().setMaxLength(100).build());

		assertField(products,
			new ObjectArrayField
				.Builder("coverages")
				.setValidator(this::assertCoverages)
				.build());

		assertField(products,
			new BooleanField
				.Builder("traits")
				.build());

		assertField(products,
			new BooleanField
				.Builder("microinsurance")
				.build());

		assertField(products,
			new ObjectArrayField.Builder("validity")
				.setValidator(validity -> {
					assertField(validity,
						new StringArrayField
							.Builder("term")
							.setEnums(TERM)
							.setMaxLength(23)
							.build());

					assertField(validity,
						new StringField
							.Builder("termOthers")
							.setMaxLength(100)
							.setOptional()
							.build());
				}).build());

		assertField(products,
			new StringArrayField
				.Builder("premiumRates")
				.setMaxLength(1024)
				.setOptional()
				.build());

		assertField(products,
			new ObjectField.Builder("termsAndConditions")
				.setValidator(termsAndConditions -> {
					assertField(termsAndConditions,
						new StringField
							.Builder("susepProcessNumber")
							.setOptional()
							.setMaxLength(20)
							.build());

					assertField(termsAndConditions,
						new StringField
							.Builder("definition")
							.setMaxLength(1024)
							.build());
				}).build());

		assertField(products,
			new ObjectField.Builder("minimumRequirements")
				.setValidator(minimumRequirements -> assertField(minimumRequirements,
					new StringArrayField
						.Builder("targetAudiences")
						.setEnums(TARGET_AUDIENCE)
						.setMaxLength(15)
						.build())).build());

	}

	private void assertCoverages(JsonObject coverages) {
		assertField(coverages,
			new StringField
				.Builder("coverage")
				.setEnums(COVERAGE)
				.setMaxLength(78)
				.build());

		assertField(coverages,
			new StringField
				.Builder("coverageDescription")
				.setMaxLength(3000)
				.build());

		assertField(coverages,
			new ObjectField
				.Builder("coverageAttributes")
				.setValidator(this::assertCoverageAttributes)
				.build());

		assertField(coverages,
			new BooleanField
				.Builder("allowApartPurchase")
				.build());
	}

	private void assertCoverageAttributes(JsonObject coverageAttributes) {
		assertField(coverageAttributes,
			new ObjectField
				.Builder("maxLMI")
				.setValidator(this::assertValue)
				.build());
	}

	public void assertValue(JsonObject minValue) {
		assertField(minValue,
			new NumberField
				.Builder("amount")
				.build());

		assertField(minValue,
			new ObjectField
				.Builder("unit")
				.setValidator(this::assertUnit)
				.build());
	}

	public void assertUnit(JsonObject unit) {
		assertField(unit,
			new StringField
				.Builder("code")
				.setMaxLength(2)
				.build());

		assertField(unit,
			new StringField
				.Builder("description")
				.setMaxLength(5)
				.build());
	}
}
