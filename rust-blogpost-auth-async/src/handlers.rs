use crate::{
    jwt_auth,
    model::{ LoginUserSchema, RegisterUserSchema, TokenClaims, User },
    response::FilteredUser,
    AppState,
};
use actix_web::{
    cookie::{ time::Duration as ActixWebDuration, Cookie },
    get,
    post,
    web,
    HttpMessage,
    HttpRequest,
    HttpResponse,
    Responder,
};
use argon2::{
    password_hash::{ rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString },
    Argon2,
};
use chrono::{ prelude::*, Duration };
use jsonwebtoken::{ encode, EncodingKey, Header };
use serde_json::json;
use sqlx::Row;

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_owned(),
        name: user.name.to_owned(),
        photo: user.photo.to_owned(),
        role: user.role.to_owned(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}

#[post("/auth/register")]
async fn register_user_handler(
    body: web::Json<RegisterUserSchema>,
    data: web::Data<AppState>
) -> impl Responder {
    let exists: bool = sqlx
        ::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(body.email.to_owned())
        .fetch_one(&data.db).await
        .unwrap()
        .get(0);

    if exists {
        return HttpResponse::Conflict().json(
            serde_json::json!({"status": "fail","message": "User with that email already exists"})
        );
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("Error while hashing password")
        .to_string();
    let query_result = sqlx
        ::query_as!(
            User,
            "INSERT INTO users (name,email,password) VALUES ($1, $2, $3) RETURNING *",
            body.name.to_string(),
            body.email.to_string().to_lowercase(),
            hashed_password
        )
        .fetch_one(&data.db).await;

    match query_result {
        Ok(user) => {
            let user_response =
                serde_json::json!({"status": "success","data": serde_json::json!({
                "user": filter_user_record(&user)
            })});

            return HttpResponse::Ok().json(user_response);
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(
                serde_json::json!({"status": "error","message": format!("{:?}", e)})
            );
        }
    }
}
