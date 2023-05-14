package kz.bars.family.budget.user.api.payload.request;

import lombok.Data;

import java.time.LocalDate;

@Data
public class ProfileUpdateRequest {

    private String firstName;
    private String lastName;
    private LocalDate birthDay;

}
