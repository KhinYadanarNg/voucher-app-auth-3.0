package voucher.management.app.auth.dto;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponseDTO {

	private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
    private UserDTO user;
}
