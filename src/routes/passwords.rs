use actix_web::{
    delete,
    error::{ErrorBadRequest, ErrorForbidden, ErrorInternalServerError, ErrorNotFound},
    get, post, put, web, Error, HttpRequest, HttpResponse,
};
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    Aes128Gcm, Nonce,
};
use diesel::{
    prelude::*,
    r2d2::{self, ConnectionManager},
    result::{DatabaseErrorKind, Error as DbError},
};
use dotenvy::dotenv;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng as RandOsRng, RngCore};
use std::env;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

use crate::db::schema::passwords::dsl;
use crate::db::user::UserClaim;
use crate::types::response::{ErrorCode, ErrorResponse, PasswordResponse};
use crate::{
    db::password::{NewPassword, Password, PasswordForm, UpdatePasswordForm},
    types::password::ReturnPassword,
};

#[allow(clippy::collapsible_match)]
#[post("/passwords/create")]
pub async fn create_password(
    req: HttpRequest,
    db_pool: web::Data<DbPool>,
    password_form: web::Json<PasswordForm>,
) -> Result<HttpResponse, Error> {
    let user_session = req
        .cookie("user_session")
        .ok_or_else(|| ErrorBadRequest("User not logged in"))?;
    dotenv().ok();

    let jwt_key = env::var("JWT_SECRET").expect("JWT must be set");
    let user = decode::<UserClaim>(
        user_session.value(),
        &DecodingKey::from_secret(jwt_key.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| ErrorForbidden("Validation failed"))?
    .claims;

    let mut rng = RandOsRng;
    let mut nonce_bytes = [0u8; 12];
    let key = Aes128Gcm::generate_key(&mut OsRng);

    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes128Gcm::new(&key);

    let cipher_text = cipher
        .encrypt(nonce, password_form.value.as_ref())
        .expect("Failed to encrypt");

    let new_password = NewPassword {
        name: password_form.name.clone(),
        username: password_form.username.clone(),
        website: password_form.website.clone(),
        note: password_form.note.clone(),
        user_id: user.id,
        value: Some(cipher_text),
        nonce: Some(nonce.to_vec()),
        key: Some(key.to_vec()),
    };

    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");

        // Insert new password
        let result = diesel::insert_into(dsl::passwords)
            .values(new_password)
            .get_result::<Password>(&mut conn);

        // Error handling
        if let Err(error) = result {
            if let DbError::DatabaseError(kind, _) = error {
                if let DatabaseErrorKind::UniqueViolation = kind {
                    return Err(ErrorResponse {
                        code: ErrorCode::BadRequest,
                        msg: "That name already exists".to_string(),
                    });
                }
            }
            return Err(ErrorResponse {
                code: ErrorCode::InternalServer,
                msg: "Internal Server Error".to_string(),
            });
        }

        let password = result.unwrap();
        Ok(password)
    })
    .await?;

    if let Err(err) = result {
        match err.code {
            ErrorCode::BadRequest => return Err(ErrorBadRequest(err.msg)),
            ErrorCode::Forbidden => return Err(ErrorForbidden(err.msg)),
            ErrorCode::NotFound => return Err(ErrorNotFound(err.msg)),
            ErrorCode::InternalServer => return Err(ErrorInternalServerError(err.msg)),
        }
    }

    let password = result.unwrap();

    Ok(HttpResponse::Ok().json(password))
}

#[get("/passwords/users")]
pub async fn get_passwords_by_user_id(
    req: HttpRequest,
    db_pool: web::Data<DbPool>,
) -> Result<HttpResponse, Error> {
    let user_session = req
        .cookie("user_session")
        .ok_or_else(|| ErrorBadRequest("User not logged in"))?;
    dotenv().ok();

    let jwt_key = env::var("JWT_SECRET").expect("JWT must be set");
    let user = decode::<UserClaim>(
        user_session.value(),
        &DecodingKey::from_secret(jwt_key.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| ErrorForbidden("Validation failed"))?
    .claims;

    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        dsl::passwords
            .filter(dsl::user_id.eq(user.id))
            .load::<Password>(&mut conn)
    })
    .await?;

    if result.is_err() {
        return Err(ErrorInternalServerError("Internal Server Error"));
    }

    let passwords = result.unwrap();
    let return_passwords: Vec<ReturnPassword> = passwords
        .iter()
        .map(|password| ReturnPassword {
            id: password.id.clone(),
            name: password.name.clone(),
            username: password.username.clone(),
            website: password.website.clone(),
            note: password.note.clone(),
            created_at: password.created_at.clone(),
            updated_at: password.updated_at.clone(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(return_passwords))
}

#[get("/passwords/name/{name}")]
pub async fn get_password_by_name(
    req: HttpRequest,
    db_pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let user_session = req
        .cookie("user_session")
        .ok_or_else(|| ErrorBadRequest("User not logged in"))?;
    dotenv().ok();

    let jwt_key = env::var("JWT_SECRET").expect("JWT must be set");
    let user = decode::<UserClaim>(
        user_session.value(),
        &DecodingKey::from_secret(jwt_key.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| ErrorForbidden("Validation failed"))?
    .claims;

    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        dsl::passwords
            .filter(dsl::name.eq(name.to_owned()))
            .filter(dsl::user_id.eq(user.id))
            .first::<Password>(&mut conn)
            .optional()
    })
    .await?;

    if result.is_err() {
        return Err(ErrorInternalServerError("Internal Server Error"));
    }

    let password = match result.unwrap() {
        Some(password) => password,
        None => return Err(ErrorNotFound("Not Found")),
    };

    let key_bytes = password.key;
    let nonce_bytes = password.nonce;
    let key = GenericArray::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let value = password.value;

    let cipher = Aes128Gcm::new(key);

    let decoded = cipher.decrypt(nonce, value.as_ref()).unwrap();

    let plain_text = String::from_utf8(decoded).unwrap();

    Ok(HttpResponse::Ok().json(PasswordResponse {
        id: password.id,
        name: password.name,
        value: plain_text,
        website: password.website,
        note: password.note,
    }))
}

#[get("/passwords/{id}")]
pub async fn get_password_by_id(
    req: HttpRequest,
    db_pool: web::Data<DbPool>,
    id: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let user_session = req
        .cookie("user_session")
        .ok_or_else(|| ErrorBadRequest("User not logged in"))?;
    dotenv().ok();

    let jwt_key = env::var("JWT_SECRET").expect("JWT must be set");
    let user = decode::<UserClaim>(
        user_session.value(),
        &DecodingKey::from_secret(jwt_key.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| ErrorForbidden("Validation failed"))?
    .claims;

    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        dsl::passwords
            .filter(dsl::id.eq(id.to_owned()))
            .filter(dsl::user_id.eq(user.id))
            .first::<Password>(&mut conn)
            .optional()
    })
    .await?;

    if result.is_err() {
        return Err(ErrorInternalServerError("Internal Server Error"));
    }

    let password = match result.unwrap() {
        Some(password) => password,
        None => return Err(ErrorNotFound("Not Found")),
    };

    let key_bytes = password.key;
    let nonce_bytes = password.nonce;
    let key = GenericArray::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let value = password.value;

    let cipher = Aes128Gcm::new(key);

    let decoded = cipher.decrypt(nonce, value.as_ref()).unwrap();

    let plain_text = String::from_utf8(decoded).unwrap();

    Ok(HttpResponse::Ok().json(PasswordResponse {
        id: password.id,
        name: password.name,
        value: plain_text,
        website: password.website,
        note: password.note,
    }))
}

#[allow(clippy::collapsible_match)]
#[allow(clippy::question_mark)]
#[put("/passwords/name/{name}")]
pub async fn update_password(
    req: HttpRequest,
    db_pool: web::Data<DbPool>,
    name: web::Path<String>,
    password_form: web::Json<UpdatePasswordForm>,
) -> Result<HttpResponse, Error> {
    let user_session = req
        .cookie("user_session")
        .ok_or_else(|| ErrorBadRequest("User not logged in"))?;
    dotenv().ok();

    let jwt_key = env::var("JWT_SECRET")
        .map_err(|_| ErrorInternalServerError("Internal Server Error"))
        .unwrap();
    let user = decode::<UserClaim>(
        user_session.value(),
        &DecodingKey::from_secret(jwt_key.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| ErrorForbidden("Validation failed"))?
    .claims;

    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");

        let password = diesel::update(
            dsl::passwords
                .filter(dsl::name.eq(name.clone()))
                .filter(dsl::user_id.eq(user.id.clone())),
        )
        .set((
            dsl::name.eq(password_form.name.to_owned()),
            dsl::username.eq(password_form.username.to_owned()),
            dsl::website.eq(password_form.website.to_owned()),
            dsl::note.eq(password_form.note.to_owned()),
        ))
        .get_result::<Password>(&mut conn);

        if password.is_err() {
            return password;
        }

        if let Some(value) = &password_form.value {
            let key_bytes = &password.as_ref().unwrap().key;
            let nonce_bytes = &password.as_ref().unwrap().nonce;
            let key = GenericArray::from_slice(key_bytes);
            let nonce = Nonce::from_slice(nonce_bytes);

            let cipher = Aes128Gcm::new(key);

            let cipher_text = cipher
                .encrypt(nonce, value.as_ref())
                .expect("Failed to encrypt");

            diesel::update(
                dsl::passwords
                    .filter(dsl::user_id.eq(user.id))
                    .filter(dsl::name.eq(name.into_inner())),
            )
            .set(dsl::value.eq(cipher_text))
            .get_result::<Password>(&mut conn)
        } else {
            password
        }
    })
    .await?;

    // Error handling
    if let Err(error) = result {
        if let DbError::DatabaseError(kind, _) = error {
            if let DatabaseErrorKind::UniqueViolation = kind {
                return Err(ErrorBadRequest("That name already exists"));
            }
        }
        return Err(ErrorInternalServerError("Internal Server Error"));
    }

    Ok(HttpResponse::Ok().json("Password Updated"))
}

#[delete("/passwords/delete/{name}")]
pub async fn delete_password(
    req: HttpRequest,
    db_pool: web::Data<DbPool>,
    name: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let user_session = req
        .cookie("user_session")
        .ok_or_else(|| ErrorBadRequest("User not logged in"))?;
    dotenv().ok();

    let jwt_key = env::var("JWT_SECRET")
        .map_err(|_| ErrorInternalServerError("Internal Server Error"))
        .unwrap();
    let user = decode::<UserClaim>(
        user_session.value(),
        &DecodingKey::from_secret(jwt_key.as_ref()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| ErrorForbidden("Validation failed"))?
    .claims;

    let count = web::block(move || {
        let mut conn = db_pool.get().expect("Failed to connect to the database");
        diesel::delete(
            dsl::passwords
                .filter(dsl::user_id.eq(user.id))
                .filter(dsl::name.eq(name.to_owned())),
        )
        .execute(&mut conn)
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    if count == 0 {
        Err(ErrorNotFound("Password not exist"))
    } else {
        Ok(HttpResponse::Ok().json("Deleted password"))
    }
}
