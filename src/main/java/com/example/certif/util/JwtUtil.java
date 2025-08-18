package com.example.certif.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    // Base64 인코딩된 32바이트(256비트) 이상 키를 환경변수로 주입
    @Value("${JWT_SECRET}")
    private String secretBase64;

    private final long ACCESS_EXPIRATION  = 1000L * 60 * 60;          // 1시간
    private final long REFRESH_EXPIRATION = 1000L * 60 * 60 * 24 * 7;  // 7일

    private Key getKey() {
        if (secretBase64 == null || secretBase64.isBlank()) {
            throw new IllegalStateException("JWT_SECRET is missing. Set it via environment variable");
        }
        byte[] keyBytes = Decoders.BASE64.decode(secretBase64); // 32바이트 이상
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /* ==== 생성부 ==== */

    // Access Token 생성: 엔티티 대신 값만 받음
    public String generateAccessToken(Long userId, String email, String nickname) {
        return Jwts.builder()
                .setSubject(email)
                .claim("userId", userId)
                .claim("nickname", nickname)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXPIRATION))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh Token 생성: 이메일만 필요
    public String generateRefreshToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /* ==== 파싱/검증부 ==== */

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(getKey()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Long getUserIdFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("userId", Long.class);
    }

    public String getEmailFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
