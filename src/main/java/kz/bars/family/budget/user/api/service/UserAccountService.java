package kz.bars.family.budget.user.api.service;

import kz.bars.family.budget.user.api.payload.request.PasswordUpdateRequest;
import kz.bars.family.budget.user.api.payload.request.ProfileUpdateRequest;
import kz.bars.family.budget.user.api.payload.request.SignupRequest;

public interface UserAccountService {
    SignupRequest registerUserDto(SignupRequest signupRequest);
    PasswordUpdateRequest updateUserDtoPassword(PasswordUpdateRequest passwordUpdateRequest);
    ProfileUpdateRequest updateUserDtoProfile(ProfileUpdateRequest profileUpdateRequest);

}
