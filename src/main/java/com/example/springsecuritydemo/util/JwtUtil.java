package com.example.springsecuritydemo.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class JwtUtil {

    public static String generateToken(String username, String issuer, Date expireDate, List<String> authorities) {
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        return JWT.create()
            .withSubject(username)
            .withExpiresAt(expireDate)
            .withIssuer(issuer)
            .withIssuedAt(new Date())
            .withClaim("roles", authorities)
            .sign(algorithm);
    }

    public static void addTokensToResponse(HttpServletResponse response, String refreshToken, String accessToken) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    public static DecodedJWT getDecodedJWT(String token) {
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        JWTVerifier verifier = JWT.require(algorithm).build();
        return verifier.verify(token);
    }

}
