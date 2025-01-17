package net.openid.conformance.token;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonObject;
import org.apache.commons.lang3.RandomStringUtils;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;

import com.google.common.collect.Lists;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.IndexOptions;

import net.openid.conformance.security.AuthenticationFacade;

@Service
@SuppressWarnings("rawtypes")
public class DBTokenService implements TokenService {

	public static final String COLLECTION = "API_TOKEN";

	public static final long DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
	public static final int TOKEN_BYTES = 64;

	@Autowired
	private MongoTemplate mongoTemplate;

	@Autowired
	private AuthenticationFacade authenticationFacade;

	@Override
	public Map createToken(boolean permanent) {

		String id = RandomStringUtils.randomAlphanumeric(13);

		byte[] tokenBytes = new byte[TOKEN_BYTES];
		new SecureRandom().nextBytes(tokenBytes);

		JsonObject jsonObject = authenticationFacade.getUserInfo().toJson();
		// gitlab includes this in it's userinfo, but this keyname is not valid in mongodb. We don't need the data
		// contained here currently, so just remove it.
		jsonObject.remove("https://gitlab.org/claims/groups/owner");
		Document token = new Document()
				.append("_id", id)
				.append("owner", authenticationFacade.getPrincipal())
				.append("info", Document.parse(jsonObject.toString()))
				.append("token", Base64Utils.encodeToString(tokenBytes))
				.append("expires", permanent ? null : System.currentTimeMillis() + DEFAULT_TTL_MS);

		mongoTemplate.insert(token, COLLECTION);
		return token;
	}

	@Override
	public boolean deleteToken(String id) {

		Criteria criteria = new Criteria("_id").is(id);
		criteria.and("owner").is(authenticationFacade.getPrincipal());
		Query query = new Query(criteria);
		return mongoTemplate.remove(query, COLLECTION).wasAcknowledged();
	}

	@Override
	public List<Map> getAllTokens() {

		Criteria criteria = new Criteria("owner").is(authenticationFacade.getPrincipal());

		Query query = new Query(criteria);
		query.fields()
				.include("_id")
				.include("expires");

		return Lists.newArrayList(mongoTemplate.getCollection(COLLECTION).find(query.getQueryObject()).projection(query.getFieldsObject()));
	}

	@Override
	public Map findToken(String token) {

		Criteria criteria = new Criteria("token").is(token);
		Query query = new Query(criteria);

		return mongoTemplate.getCollection(COLLECTION).find(query.getQueryObject()).first();
	}

	@Override
	public void createIndexes() {

		MongoCollection<Document> collection = mongoTemplate.getCollection(COLLECTION);
		collection.createIndex(new Document("owner", 1));
		collection.createIndex(new Document("token", 1), new IndexOptions().unique(true));
	}
}
