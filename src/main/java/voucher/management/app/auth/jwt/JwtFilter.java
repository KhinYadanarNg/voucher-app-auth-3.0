package voucher.management.app.auth.jwt;

import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuditLogInvalidUser;
import voucher.management.app.auth.enums.AuditLogResponseStatus;
import voucher.management.app.auth.service.impl.AuditLogService;
import voucher.management.app.auth.service.impl.JWTService;
import voucher.management.app.auth.service.impl.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	private JWTService jwtService;

	@Autowired
	ApplicationContext context;
	
	@Autowired
	private AuditLogService auditLogService;
	
	private String userID;
	private String apiEndpoint;
	private String httpMethod;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
//		 Optional<String> refreshTokenOpt = CookieUtils.getCookieValue(request, "refresh_token");
//		 Optional<String> accessTokenOpt = CookieUtils.getCookieValue(request, "access_token");
//		 String refreshToken = "";
//		 String accessToken = "";
//		 
//		 if (accessTokenOpt.isPresent()) {
//			 accessToken = accessTokenOpt.get();
//		 }
//		 
//		 if (refreshTokenOpt.isPresent()) {
//             refreshToken = refreshTokenOpt.get();
//	 }
		
		String authHeader = request.getHeader("Authorization");
	    userID = request.getHeader("X-User-Id");
	    apiEndpoint = request.getRequestURI();
	    httpMethod = request.getMethod();

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		String jwtToken = authHeader.substring(7); // Remove "Bearer " prefix
		String username = null;

		try {
			username = jwtService.extractUserName(jwtToken); // Extract username from token
		} catch (ExpiredJwtException e) {
			handleException(response, "JWT token is expired", HttpServletResponse.SC_UNAUTHORIZED);
			return;
		} catch (MalformedJwtException e) {
			handleException(response, "Invalid JWT token", HttpServletResponse.SC_BAD_REQUEST);
			return;
		} catch (SecurityException e) {
			handleException(response, "JWT signature is invalid", HttpServletResponse.SC_UNAUTHORIZED);
			return;
		} catch (Exception e) {
			handleException(response, "Error processing JWT token", HttpServletResponse.SC_BAD_REQUEST);
			return;
		}

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			User user = context.getBean(UserService.class).findByEmail(username);
			UserDetails userDetails = org.springframework.security.core.userdetails.User
					.withUsername(user.getUsername()).password(user.getPassword()).roles(user.getRole().toString())
					.build();
			if (jwtService.validateToken(jwtToken, userDetails)) {
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}

		filterChain.doFilter(request, response);
	}

	private void handleException(HttpServletResponse response, String message, int status) throws IOException {
		TokenErrorResponse.sendErrorResponse(response, message, status, "UnAuthorized");
		auditLogService.sendAuditLogToSqs(Integer.toString(status), userID, AuditLogInvalidUser.InvalidUserName.toString(), "", message, apiEndpoint, AuditLogResponseStatus.FAILED.toString(), httpMethod, message);
	}
}
