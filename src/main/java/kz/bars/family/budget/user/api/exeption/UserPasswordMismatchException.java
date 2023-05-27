package kz.bars.family.budget.user.api.exeption;

public class UserPasswordMismatchException extends RuntimeException {

    public UserPasswordMismatchException(String message) {
        super(message);
    }

}