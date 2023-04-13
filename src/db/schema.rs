// @generated automatically by Diesel CLI.

diesel::table! {
    passwords (id) {
        id -> Varchar,
        name -> Varchar,
        nonce -> Bytea,
        value -> Bytea,
        key -> Bytea,
        user_id -> Varchar,
    }
}

diesel::table! {
    users (id) {
        id -> Varchar,
        username -> Varchar,
        email -> Varchar,
        password -> Varchar,
    }
}

diesel::joinable!(passwords -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    passwords,
    users,
);
