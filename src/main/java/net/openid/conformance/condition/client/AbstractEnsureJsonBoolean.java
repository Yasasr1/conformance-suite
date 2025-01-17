package net.openid.conformance.condition.client;

import com.google.gson.JsonElement;
import net.openid.conformance.condition.AbstractCondition;
import net.openid.conformance.testmodule.Environment;
import net.openid.conformance.testmodule.OIDFJSON;

public abstract class AbstractEnsureJsonBoolean extends AbstractCondition {

	public Environment validate(Environment env, String key, String path, boolean mayBeAbsent, boolean mayBeJsonNull) {

		JsonElement parameterValue = env.getElementFromObject(key, path);
		String errorMessage = null;
		boolean isAbsent = false;
		boolean isJsonNull = false;

		if (parameterValue == null) {
			isAbsent = true;
			if (!mayBeAbsent) {
				errorMessage = "'" + key + "." + path + "' is required but absent.";
			}
		} else {
			if (parameterValue.isJsonNull()) {
				isJsonNull = true;
				if (!mayBeJsonNull) {
					errorMessage = "'" + key + "." + path + "' is json 'null'.";
				}
			}
			else if (parameterValue.isJsonPrimitive()) {
				if (!parameterValue.getAsJsonPrimitive().isBoolean()) {
					errorMessage = key + "." + path + ": incorrect type, must be a boolean.";
				}
			} else {
				errorMessage = key + "." + path + ": incorrect type, must be a boolean.";
			}
		}

		if (errorMessage != null) {
			throw error(errorMessage, args("key", key, "path", path));
		}
		if(isJsonNull) {
			logSuccess(key + "." + path + " is json null which is allowed");
		} else if(isAbsent) {
			logSuccess(key + "." + path + " is absent which is allowed");
		} else {
			logSuccess(key + "." + path + " is boolean");
		}

		return env;
	}

}
