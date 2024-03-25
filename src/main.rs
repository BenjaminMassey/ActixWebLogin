use actix_web::{cookie::Key, App, HttpServer, HttpResponse};
use actix_identity::IdentityMiddleware;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{get, post, Responder, HttpRequest, HttpMessage};
use actix_identity::Identity;
use actix_web::web;
use serde::Deserialize;
use actix_web::web::Redirect;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};

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
struct Info {
    name: String,
}

#[post("/do_login")]
async fn do_login(request: HttpRequest, web::Form(form): web::Form<Info>) -> impl Responder {
    // Some kind of authentication should happen here
    // e.g. password-based, biometric, etc.
    // [...]
    
    let mut user_exists = false;
    let file = File::open("accounts.txt").unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        if line.unwrap() == form.name.clone() {
            user_exists = true;
            break;
        }
    }

    if user_exists {
        // attach a verified user identity to the active session
        Identity::login(&request.extensions(), form.name.clone().into()).unwrap();
        return Redirect::to("/").see_other();
    }

    Redirect::to("/login").see_other() // TODO: message
}

#[get("/login")]
async fn login() -> impl Responder {
    HttpResponse::Ok().body(std::fs::read_to_string("./templates/login.html").unwrap())
}

#[post("/do_create_account")]
async fn do_create_account(request: HttpRequest, web::Form(form): web::Form<Info>) -> impl Responder {
    // TODO: do not create if already exist
    let mut file = File::options().write(true).append(true).open("accounts.txt").unwrap();
    file.write(format!("{}\n", form.name.clone()).as_bytes()).unwrap();
    Identity::login(&request.extensions(), form.name.clone().into()).unwrap();
    Redirect::to("/").see_other()
}

#[get("/create_account")]
async fn create_account() -> impl Responder {
    HttpResponse::Ok().body(std::fs::read_to_string("./templates/create_account.html").unwrap())
}

#[get("/logout")]
async fn logout(user: Option<Identity>) -> impl Responder {
    if user.is_some() {
        user.unwrap().logout();
    }
    Redirect::to("/").see_other() // TODO: messaging
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // When using `Key::generate()` it is important to initialize outside of the
    // `HttpServer::new` closure. When deployed the secret key should be read from a
    // configuration file or environment variables.
    let secret_key = Key::generate();

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
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}