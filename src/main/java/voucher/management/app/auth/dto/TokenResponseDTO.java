package voucher.management.app.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenResponseDTO {

	private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
}
