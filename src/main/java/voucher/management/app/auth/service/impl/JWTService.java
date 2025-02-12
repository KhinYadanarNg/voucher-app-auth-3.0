package voucher.management.app.auth.service.impl;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JWTService {

	
	public String generateToken(String userName, String userEmail, Boolean isRefreshToke) {
		Integer tokenValidDuration = isRefreshToke  ? 120 : 30;
		Map<String, Object> claims = new HashMap<>();
		claims.put("userEmail", userEmail);
		claims.put("userName", userName);	
		return Jwts.builder().claims().add(claims).subject(userEmail).issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + 60 * 60 * tokenValidDuration)).and().signWith(getKey()).compact();
	}

	private SecretKey getKey() {
		String jwtSecretKey = System.getenv("JWT_SECRET");
		byte[] keyBytes = Decoders.BASE64.decode(jwtSecretKey);
		return Keys.hmacShaKeyFor(keyBytes);
	}

	


}
