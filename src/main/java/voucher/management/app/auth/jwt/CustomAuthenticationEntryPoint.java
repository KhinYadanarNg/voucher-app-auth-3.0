package voucher.management.app.auth.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {

		Throwable cause = authException.getCause(); // Get the root cause

		if (cause instanceof ExpiredJwtException) {
			// Token has expired
			TokenErrorResponse.sendErrorResponse(response, "Your token has expired. Please refresh or reauthenticate.",
					HttpServletResponse.SC_UNAUTHORIZED, "Token Expired");
		} else if (cause instanceof SecurityException || cause instanceof MalformedJwtException) {
			// Token is invalid
			TokenErrorResponse.sendErrorResponse(response, "The provided token is invalid.",
					HttpServletResponse.SC_BAD_REQUEST, "Invalid Token");
		} else if (cause instanceof UnsupportedJwtException) {
			// Token is unsupported
			TokenErrorResponse.sendErrorResponse(response, "The provided token is not supported.",
					HttpServletResponse.SC_UNAUTHORIZED, "Unsupported Token");

		} else {
			// Other authentication failures
			TokenErrorResponse.sendErrorResponse(response, "Authentication Failed.",
					HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());

		}

	}
}
