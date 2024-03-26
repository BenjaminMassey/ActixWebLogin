use actix_web::{cookie::Key, App, HttpServer, HttpResponse};
use actix_identity::IdentityMiddleware;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{get, post, Responder, HttpRequest, HttpMessage};
use actix_identity::Identity;
use actix_web::web;
use serde::Deserialize;
use actix_web::web::Redirect;
use rusqlite::{Connection, Result};
use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Pbkdf2
};

#[get("/")]
async fn index(user: Option<Identity>) -> impl Responder {
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
async fn do_login(request: HttpRequest, web::Form(form): web::Form<FormInfo>) -> impl Responder {
    let result = get_user_info_sqlite(form.name.clone());
    if result.is_none() {
        return Redirect::to("/login/User%20Not%20Found").see_other();
    }
    if Pbkdf2.verify_password(
            form.password.clone().as_bytes(),
            &PasswordHash::new(&result.unwrap().password).unwrap()
        ).is_err() {
        return Redirect::to("/login/Password%20Is%20Incorrect").see_other();
    }
    Identity::login(&request.extensions(), form.name.clone().into()).unwrap();
    Redirect::to("/").see_other()
}
#[get("/login")]
async fn login() -> impl Responder {
    HttpResponse::Ok().body(login_html(""))
}
#[get("/login/{message}")]
async fn login_message(message: Option<web::Path<String>>) -> impl Responder {
    HttpResponse::Ok().body(login_html(&message.unwrap()))
}
fn login_html(message: &str) -> String {
    let html = std::fs::read_to_string("./templates/login.html").unwrap();
    html.replace("[[[MESSAGE]]]", message)
}

#[post("/do_create_account")]
async fn do_create_account(request: HttpRequest, web::Form(form): web::Form<FormInfo>) -> impl Responder {
    let result = get_user_info_sqlite(form.name.clone());
    if result.is_some() {
        return Redirect::to("/create_account/Username%20already%20exists.").see_other();
    }
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Pbkdf2.hash_password(form.password.as_bytes(), &salt).unwrap().to_string();
    let _ = insert_user_sqlite(form.name.clone(), password_hash);
    Identity::login(&request.extensions(), form.name.clone().into()).unwrap();
    Redirect::to("/").see_other()
}
#[get("/create_account")]
async fn create_account() -> impl Responder {
    HttpResponse::Ok().body(create_account_html(""))
}
#[get("/create_account/{message}")]
async fn create_account_message(message: Option<web::Path<String>>) -> impl Responder {
    HttpResponse::Ok().body(create_account_html(&message.unwrap()))
}
fn create_account_html(message: &str) -> String {
    let html = std::fs::read_to_string("./templates/create_account.html").unwrap();
    html.replace("[[[MESSAGE]]]", message)
}

#[get("/logout")]
async fn logout(user: Option<Identity>) -> impl Responder {
    if user.is_some() {
        user.unwrap().logout();
    }
    Redirect::to("/").see_other() // TODO: messaging
}

fn insert_user_sqlite(username: String, password: String) -> Result<()> {
    let mut conn = Connection::open("accounts.db")?;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO users (username, password) VALUES (?1, ?2)",
        &[&username, &password],
    )?;
    tx.commit()?;
    Ok(())
}

struct UserInfo {
    username: String,
    password: String,
}

fn get_user_info_sqlite(username: String) -> Option<UserInfo> {
    let conn = Connection::open("accounts.db").unwrap();
    let mut stmt = conn.prepare("SELECT * FROM users WHERE username = ?1").unwrap();
    let mut rows = stmt.query([&username]).unwrap();
    if let Some(row) = rows.next().unwrap() {
        //let username: String = row.get(0).unwrap();
        let password: String = row.get(1).unwrap();
        Some(UserInfo {username, password})
    } else {
        None
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // When using `Key::generate()` it is important to initialize outside of the
    // `HttpServer::new` closure. When deployed the secret key should be read from a
    // configuration file or environment variables.
    let secret_key = Key::generate();

    let conn = Connection::open("accounts.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
             username TEXT PRIMARY KEY,
             password TEXT)",
        [],
    ).unwrap();

    HttpServer::new(move || {
        App::new()
            // Install the identity framework first.
            .wrap(IdentityMiddleware::default())
            // The identity system is built on top of sessions. You must install the session
            // middleware to leverage `actix-identity`. The session middleware must be mounted
            // AFTER the identity middleware: `actix-web` invokes middleware in the OPPOSITE
            // order of registration when it receives an incoming request.
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone(),
            ))
        .service(index)
        .service(login)
        .service(logout)
        .service(do_login)
        .service(create_account)
        .service(do_create_account)
        .service(login_message)
        .service(create_account_message)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}