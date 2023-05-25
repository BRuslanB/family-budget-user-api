INSERT INTO role (name, role)
VALUES ('ADMINISTRATOR', 'ROLE_ADMIN'),
       ('USER', 'ROLE_USER');

INSERT INTO users (email, firstname, lastname, birth_day, password, token_uuid)
VALUES ('admin@gmail.com', 'Иванов', 'Иван', '1986-01-01', '$2a$10$7VB4nxLa.hxOjL5/NafMLuFPndVGkRZ7FbNfOk44ktBS8h8aqxTsS', null),
       ('abramov@gmail.com', 'Абрамов', 'Никита', '2000-02-24', '$2a$10$7VB4nxLa.hxOjL5/NafMLuFPndVGkRZ7FbNfOk44ktBS8h8aqxTsS', null),
       ('omarov@gmail.com', 'Омаров', 'Ержан', '1984-03-22', '$2a$10$7VB4nxLa.hxOjL5/NafMLuFPndVGkRZ7FbNfOk44ktBS8h8aqxTsS', null),
       ('achmetov@gmail.com', 'Ахметов', 'Берик', '1977-07-07', '$2a$10$7VB4nxLa.hxOjL5/NafMLuFPndVGkRZ7FbNfOk44ktBS8h8aqxTsS', null);

INSERT INTO users_roles (user_id, roles_id)
VALUES (1, 1),
       (2, 2),
       (3, 2),
       (4, 2);