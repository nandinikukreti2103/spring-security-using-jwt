package com.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "3c3782150403d8757118b741aeb38b2de81f04f5b60af5eb53c1c72da813c08526c7a9c2afc2ecb5fe8d68e01699278134ef3c3dec24d924706df851078bfeec4acfeeb914b242fd870e57e652e6eb2da2a887916bf99c2ea3667a805727d841f1b52c923d8166ac966cd18f9013fe845b6c21403671396c3756e68d657f4ca8333b1720cafef5f94705bb1e1c4613ee514f71f6971868bc1642a89ffc48563cf923832d8d09f04380cc4e1ad9097219a9e14c13855195b9c81a577427f69cb561932837f4222390ed1f893ee0b6f3f97761c89b2e4680d352dbc6ba9785dcdd9ee097b56b83a5c2d3fe5faf16e2c27da087559fa926c83b6cd837c4519460fa";

    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String userName = extractUsername(token);
        return(userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public String generateToken(Map<String,Object> extractClaim, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extractClaim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); // to generate token
    }

    public <T> T extractClaims(String token, Function<Claims,T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
