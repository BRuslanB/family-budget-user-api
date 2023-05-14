package kz.bars.family.budget.user.api.payload.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PasswordUpdateRequest {

    @NotEmpty(message = "Current password is required")
    @Size(min = 6)
    private String password;

    @NotEmpty(message = "New password is required")
    @Size(min = 6)
    private String newPassword;

    @NotEmpty(message = "Confirm password is required")
    @Size(min = 6)
    private String rePassword;

}
