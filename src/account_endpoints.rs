use actix_identity::Identity;
use actix_web::web;
use actix_web::web::Redirect;
use actix_web::HttpResponse;
use actix_web::{get, post, HttpMessage, HttpRequest, Responder};
use pbkdf2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use serde::Deserialize;

use crate::account_data;

#[get("/")]
pub async fn index(user: Option<Identity>) -> impl Responder {
    let html = std::fs::read_to_string("./templates/index.html").unwrap();
    let message = {
        if let Some(user) = user {
            format!("You are signed in as: {}", user.id().unwrap())
        } else {
            "You are not signed in.".to_owned()
        }
    };
    HttpResponse::Ok().body(html.replace("[[[TEXT]]]", &message))
}

#[derive(Deserialize)]
struct FormInfo {
    name: String,
    password: String,
}

#[post("/do_login")]
pub async fn do_login(request: HttpRequest, web::Form(form): web::Form<FormInfo>) -> impl Responder {
    let result = account_data::get_user_info_sqlite(form.name.clone());
    if result.is_none() {
        return Redirect::to("/login/User%20Not%20Found").see_other();
    }
    if Pbkdf2
        .verify_password(
            form.password.clone().as_bytes(),
            &PasswordHash::new(&result.unwrap().password).unwrap(),
        )
        .is_err()
    {
        return Redirect::to("/login/Password%20Is%20Incorrect").see_other();
    }
    Identity::login(&request.extensions(), form.name.clone()).unwrap();
    Redirect::to("/").see_other()
}
#[get("/login")]
pub async fn login() -> impl Responder {
    HttpResponse::Ok().body(login_html(""))
}
#[get("/login/{message}")]
pub async fn login_message(message: Option<web::Path<String>>) -> impl Responder {
    HttpResponse::Ok().body(login_html(&message.unwrap()))
}
fn login_html(message: &str) -> String {
    let html = std::fs::read_to_string("./templates/login.html").unwrap();
    html.replace("[[[MESSAGE]]]", message)
}

#[post("/do_create_account")]
pub async fn do_create_account(
    request: HttpRequest,
    web::Form(form): web::Form<FormInfo>,
) -> impl Responder {
    let result = account_data::get_user_info_sqlite(form.name.clone());
    if result.is_some() {
        return Redirect::to("/create_account/Username%20already%20exists.").see_other();
    }
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Pbkdf2
        .hash_password(form.password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let _ = account_data::insert_user_sqlite(form.name.clone(), password_hash);
    Identity::login(&request.extensions(), form.name.clone()).unwrap();
    Redirect::to("/").see_other()
}
#[get("/create_account")]
pub async fn create_account() -> impl Responder {
    HttpResponse::Ok().body(create_account_html(""))
}
#[get("/create_account/{message}")]
pub async fn create_account_message(message: Option<web::Path<String>>) -> impl Responder {
    HttpResponse::Ok().body(create_account_html(&message.unwrap()))
}
fn create_account_html(message: &str) -> String {
    let html = std::fs::read_to_string("./templates/create_account.html").unwrap();
    html.replace("[[[MESSAGE]]]", message)
}

#[get("/logout")]
pub async fn logout(user: Option<Identity>) -> impl Responder {
    if let Some(user) = user {
        user.logout();
    }
    Redirect::to("/").see_other() // TODO: messaging
}