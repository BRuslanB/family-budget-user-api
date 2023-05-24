package kz.bars.family.budget.user.api.payload.request;

import lombok.Data;

@Data
public class RefreshTokenRequest {

    private String email;
    private String tokenUUID;

}
