package kz.bars.family.budget.user.api.service;

import kz.bars.family.budget.user.api.payload.request.LoginRequest;
import kz.bars.family.budget.user.api.payload.request.RefreshTokenRequest;
import kz.bars.family.budget.user.api.payload.response.TokenSuccessResponse;

public interface UserAuthService {

    TokenSuccessResponse authenticateUser(LoginRequest loginRequest);
    TokenSuccessResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
    void logoutUser();

}
