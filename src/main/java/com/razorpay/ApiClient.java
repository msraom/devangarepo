package com.razorpay;

import java.io.IOException;
import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;

import okhttp3.Response;


class ApiClient {

  private String auth;

  private final String ENTITY = "entity";

  private final String COLLECTION = "collection";

  private final String ERROR = "error";

  private final String DESCRIPTION = "description";

  private final String STATUS_CODE = "code";

  private final int STATUS_OK = 200;

  ApiClient(String auth) {
    this.auth = auth;
  }

  <T extends Entity> T get(String path, JSONObject requestObject) throws RazorpayException {
    Response response = ApiUtils.getRequest(path, requestObject, auth);
    return processResponse(response);
  }

  <T extends Entity> T post(String path, JSONObject requestObject) throws RazorpayException {
    Response response = ApiUtils.postRequest(path, requestObject, auth);
    return processResponse(response);
  }

  <T extends Entity> ArrayList<T> getCollection(String path, JSONObject requestObject)
      throws RazorpayException {
    Response response = ApiUtils.getRequest(path, requestObject, auth);
    return processCollectionResponse(response);
  }

  private <T extends Entity> T parseResponse(JSONObject jsonObject) throws RazorpayException {
    if (jsonObject.has(ENTITY)) {
      Class<T> cls = getClass(jsonObject.getString(ENTITY));
      try {
        return cls.getConstructor(JSONObject.class).newInstance(jsonObject);
      } catch (Exception e) {
        throw new RazorpayException("Unable to parse response because of " + e.getMessage());
      }
    }

    throw new RazorpayException("Unable to parse response");
  }

  private <T extends Entity> ArrayList<T> parseCollectionResponse(JSONObject jsonObject)
      throws RazorpayException {

    ArrayList<T> modelList = new ArrayList<T>();
    if (jsonObject.has(ENTITY) && COLLECTION.equals(jsonObject.getString(ENTITY))) {
      JSONArray jsonArray = jsonObject.getJSONArray("items");
      try {
        for (int i = 0; i < jsonArray.length(); i++) {
          JSONObject refundJson = jsonArray.getJSONObject(i);
          T t = parseResponse(refundJson);
          modelList.add(t);
        }
        return modelList;
      } catch (RazorpayException e) {
        throw e;
      }
    }

    throw new RazorpayException("Unable to parse response");
  }

  private <T extends Entity> T processResponse(Response response) throws RazorpayException {
    if (response == null) {
      throw new RazorpayException("Invalid Response from server");
    }

    int statusCode = response.code();
    String responseBody = null;
    JSONObject responseJson = null;

    try {
      responseBody = response.body().string();
      responseJson = new JSONObject(responseBody);
    } catch (IOException e) {
      throw new RazorpayException(e.getMessage());
    }

    if (statusCode == STATUS_OK) {
      return parseResponse(responseJson);
    }

    throwException(statusCode, responseJson);
    return null;
  }

  private <T extends Entity> ArrayList<T> processCollectionResponse(Response response)
      throws RazorpayException {
    if (response == null) {
      throw new RazorpayException("Invalid Response from server");
    }

    int statusCode = response.code();
    String responseBody = null;
    JSONObject responseJson = null;

    try {
      responseBody = response.body().string();
      responseJson = new JSONObject(responseBody);
    } catch (IOException e) {
      throw new RazorpayException(e.getMessage());
    }

    if (statusCode == STATUS_OK) {
      return parseCollectionResponse(responseJson);
    }

    throwException(statusCode, responseJson);
    return null;
  }

  private void throwException(int statusCode, JSONObject responseJson) throws RazorpayException {
    if (responseJson.has(ERROR)) {
      JSONObject errorResponse = responseJson.getJSONObject(ERROR);
      String code = errorResponse.getString(STATUS_CODE);
      String description = errorResponse.getString(DESCRIPTION);
      throw new RazorpayException(code + ":" + description);
    }
    throwServerException(statusCode, responseJson.toString());
  }

  private void throwServerException(int statusCode, String responseBody) throws RazorpayException {
    StringBuilder sb = new StringBuilder();
    sb.append("Status Code: ").append(statusCode).append("\n");
    sb.append("Server response: ").append(responseBody);
    throw new RazorpayException(sb.toString());
  }

  private Class getClass(String entity) {
    try {
      String entityClass =
          "com.razorpay." + Character.toUpperCase(entity.charAt(0)) + entity.substring(1);
      return Class.forName(entityClass);
    } catch (ClassNotFoundException e) {
      return null;
    }
  }
}
