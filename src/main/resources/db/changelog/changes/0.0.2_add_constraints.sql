ALTER TABLE users_roles
    DROP CONSTRAINT IF EXISTS user_roles_id_fk;
ALTER TABLE users_roles
    ADD CONSTRAINT user_roles_id_fk
        FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE users_roles
    DROP CONSTRAINT IF EXISTS roles_user_id_fk;
ALTER TABLE users_roles
    ADD CONSTRAINT roles_user_id_fk
        FOREIGN KEY (roles_id) REFERENCES role(id);