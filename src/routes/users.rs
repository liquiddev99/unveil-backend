use actix_web::{
    cookie::{time, Cookie, SameSite::Lax},
    delete,
    error::{ErrorBadRequest, ErrorForbidden, ErrorInternalServerError, ErrorNotFound},
    get, post, put, web, Error, HttpRequest, HttpResponse,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::{
    prelude::*,
    r2d2::{self, ConnectionManager},
    result::{DatabaseErrorKind, Error as DbError},
};
use dotenvy::dotenv;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use regex::Regex;
use std::env;

use crate::db::schema::users::dsl::*;
use crate::db::user::{LoginUser, NewUser, User, UserClaim};
use crate::types::response::{ErrorCode, ErrorResponse, TokenResponse};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[get("/users")]
pub async fn get_users(db_pool: web::Data<DbPool>) -> Result<HttpResponse, Error> {
    let fetched_users = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        users.load::<User>(&mut conn)
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(fetched_users))
}

#[allow(clippy::collapsible_match)]
#[post("/users/signup")]
pub async fn signup(
    db_pool: web::Data<DbPool>,
    new_user_form: web::Json<NewUser>,
) -> Result<HttpResponse, Error> {
    // Check if valid email
    let email_form = &new_user_form.email;
    let email_regex = Regex::new(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$").unwrap();
    if !email_regex.is_match(email_form) {
        return Err(ErrorBadRequest("Please input a valid email"));
    }

    // Create hash password
    let hashed_password =
        hash(new_user_form.password.clone(), DEFAULT_COST).map_err(ErrorInternalServerError)?;
    let hashed_user = NewUser {
        password: hashed_password,
        ..new_user_form.into_inner()
    };

    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");

        // Insert new user
        let result = diesel::insert_into(users)
            .values(hashed_user)
            .get_result::<User>(&mut conn);

        // Error handling
        if let Err(error) = result {
            if let DbError::DatabaseError(kind, _) = error {
                if let DatabaseErrorKind::UniqueViolation = kind {
                    return Err(ErrorResponse {
                        code: ErrorCode::BadRequest,
                        msg: "Email already exists".to_string(),
                    });
                }
            }

            return Err(ErrorResponse {
                code: ErrorCode::InternalServer,
                msg: "Internal Server Error".to_string(),
            });
        }

        let user = result.unwrap();
        Ok(user)
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
    let new_user = result.unwrap();

    // Create JWT token
    let expiration = chrono::Utc::now() + chrono::Duration::hours(6);
    let user_claim = UserClaim {
        exp: expiration.timestamp(),
        id: new_user.id,
        name: new_user.username,
        email: new_user.email,
    };
    dotenv().ok();
    let jwt_key = env::var("JWT_SECRET").expect("JWT Key must be set");

    let token = encode(
        &Header::default(),
        &user_claim,
        &EncodingKey::from_secret(jwt_key.as_ref()),
    )
    .map_err(ErrorInternalServerError)?;

    let cookie = Cookie::build("user_session", token)
        .http_only(true)
        .path("/")
        .same_site(Lax)
        .max_age(time::Duration::days(1))
        .finish();

    Ok(HttpResponse::Ok().cookie(cookie).finish())
}

#[post("/users/login")]
pub async fn login(
    db_pool: web::Data<DbPool>,
    credentials: web::Json<LoginUser>,
) -> Result<HttpResponse, Error> {
    let plain_password = credentials.password.clone();
    let result = web::block(move || {
        let mut conn = db_pool
            .get()
            .expect("Failed to get a connection from the pool");
        users
            .filter(email.eq(credentials.email.to_owned()))
            .first::<User>(&mut conn)
            .optional()
    })
    .await?
    .map_err(ErrorInternalServerError)?;

    let user = match result {
        Some(user) => user,
        None => return Err(ErrorBadRequest("Invalid Credentials")),
    };

    let is_valid_password =
        verify(plain_password, &user.password).map_err(ErrorInternalServerError)?;

    if !is_valid_password {
        return Err(ErrorBadRequest("Invalid Credentials"));
    }

    let expiration = chrono::Utc::now() + chrono::Duration::hours(6);
    let user_claim = UserClaim {
        exp: expiration.timestamp(),
        id: user.id,
        name: user.username,
        email: user.email,
    };
    dotenv().ok();
    let jwt_key = env::var("JWT_SECRET").map_err(ErrorInternalServerError)?;

    let token = encode(
        &Header::default(),
        &user_claim,
        &EncodingKey::from_secret(jwt_key.as_ref()),
    )
    .map_err(ErrorInternalServerError)?;

    let cookie = Cookie::build("user_session", token)
        .http_only(true)
        .path("/")
        .same_site(Lax)
        .max_age(time::Duration::days(1))
        .finish();

    Ok(HttpResponse::Ok().cookie(cookie).finish())
}

#[post("/users/logout")]
pub async fn logout() -> Result<HttpResponse, Error> {
    let cookie = Cookie::build("user_session", "")
        .http_only(true)
        .path("/")
        .same_site(Lax)
        .max_age(time::Duration::milliseconds(0))
        .expires(time::OffsetDateTime::now_utc())
        .finish();

    Ok(HttpResponse::Ok().cookie(cookie).finish())
}
