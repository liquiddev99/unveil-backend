use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use diesel::{
    pg::PgConnection,
    r2d2::{self, ConnectionManager},
};
use dotenvy::dotenv;
use std::env;

mod db;
mod routes;
mod types;

use routes::passwords::{
    create_password, delete_password, get_password_by_id, get_password_by_name,
    get_passwords_by_user_id, update_password,
};
use routes::users::{get_users, login, logout, signup};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);
        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(get_users)
            .service(signup)
            .service(login)
            .service(logout)
            .service(create_password)
            .service(get_passwords_by_user_id)
            .service(get_password_by_name)
            .service(get_password_by_id)
            .service(update_password)
            .service(delete_password)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
