package kz.bars.family.budget.user.api.payload.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.time.LocalDate;

@Data
public class SignupRequest {

    @NotEmpty(message = "User email is required")
    private String email;

    @NotEmpty(message = "Please enter your first name")
    private String firstName;

    @NotEmpty(message = "Please enter your last name")
    private String lastName;

    @NotEmpty(message = "Please enter your birth day")
    private LocalDate birthDay;

    @NotEmpty(message = "Password is required")
    @Size(min = 6)
    private String password;

    @NotEmpty(message = "Confirm Password is required")
    @Size(min = 6)
    private String rePassword;

}
