package voucher.management.app.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponseDTO {

	private TokenResponseDTO token;
	private UserDTO user;
}
