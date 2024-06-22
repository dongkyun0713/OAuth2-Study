package com.example.oauth2_study.dto;

import java.util.Map;

public class NaverResponse implements OAuth2Response {

    private static final String RESPONSE_KEY = "response";
    private static final String ID_KEY = "id";
    private static final String EMAIL_KEY = "email";
    private static final String NAME_KEY = "name";
    private static final String INVALID_ATTRIBUTE_TYPE_MESSAGE = "잘못된 응답 속성 유형";

    private final Map<String, Object> attribute;

    public NaverResponse(Map<String, Object> attribute) {
        this.attribute = castToMap(attribute.get(RESPONSE_KEY));
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getProviderId() {
        return attribute.get(ID_KEY).toString();
    }

    @Override
    public String getEmail() {
        return attribute.get(EMAIL_KEY).toString();
    }

    @Override
    public String getName() {
        return attribute.get(NAME_KEY).toString();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> castToMap(Object obj) {
        if (obj instanceof Map) {
            return (Map<String, Object>) obj;
        } else {
            throw new IllegalArgumentException(INVALID_ATTRIBUTE_TYPE_MESSAGE);
        }
    }
}
