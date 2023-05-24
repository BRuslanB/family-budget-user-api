DROP TABLE IF EXISTS role CASCADE;
CREATE TABLE role (
    id SERIAL PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL
);

DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users (
    id SERIAL PRIMARY KEY NOT NULL,
    email TEXT UNIQUE NOT NULL,
    firstname TEXT NOT NULL,
    lastname TEXT NOT NULL,
    birth_day DATE NOT NULL,
    password TEXT NOT NULL,
    token_uuid TEXT
);

DROP TABLE IF EXISTS users_roles;
CREATE TABLE users_roles (
    user_id INT NOT NULL,
    roles_id INT NOT NULL
);