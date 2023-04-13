// @generated automatically by Diesel CLI.

diesel::table! {
    passwords (id) {
        id -> Varchar,
        name -> Varchar,
        username -> Varchar,
        value -> Bytea,
        website -> Nullable<Varchar>,
        note -> Nullable<Varchar>,
        key -> Bytea,
        nonce -> Bytea,
        user_id -> Varchar,
        created_at -> Nullable<Varchar>,
        updated_at -> Nullable<Varchar>,
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
