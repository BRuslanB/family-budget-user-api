package kz.bars.family.budget.user.api.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenSuccessResponse {

    private String access_token;
    private String refresh_token;

}
