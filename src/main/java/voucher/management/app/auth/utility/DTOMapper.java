package voucher.management.app.auth.utility;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Component;

import voucher.management.app.auth.dto.AuthResponseDTO;
import voucher.management.app.auth.dto.TokenResponseDTO;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.entity.User;

@Component
public class DTOMapper {
	

	public static UserDTO toUserDTO(User user) {
		UserDTO userDTO = new UserDTO();
		userDTO.setUserID(user.getUserId());
		userDTO.setUsername(user.getUsername());
		userDTO.setEmail(user.getEmail());
		userDTO.setRole(user.getRole());
		userDTO.setActive(user.isActive());
		userDTO.setVerified(user.isVerified());
		String[] preferences = user.getPreferences().split(",");
		if (preferences.length > 0 && !preferences[0].isEmpty()) {
			 List<String> preferencesArrayList = new ArrayList<String>(Arrays.asList(preferences));
		    userDTO.setPreferences(preferencesArrayList);
		} 
		return userDTO;
	}
	
	public static AuthResponseDTO toAuthResponseDTO(UserDTO userDTO, String accessToken, String refreshToken) {
		AuthResponseDTO authResponseDTO = new AuthResponseDTO();
		authResponseDTO.setAccessToken(accessToken);
		authResponseDTO.setRefreshToken(refreshToken);
		authResponseDTO.setUser(userDTO);
		return authResponseDTO; 
	}
	
	public static TokenResponseDTO toTokenDTO( String accessToken, String refreshToken) {
		TokenResponseDTO tokenResponseDTO = new TokenResponseDTO();
		tokenResponseDTO.setAccessToken(accessToken);
		tokenResponseDTO.setRefreshToken(refreshToken);
		return tokenResponseDTO; 
	}

}
