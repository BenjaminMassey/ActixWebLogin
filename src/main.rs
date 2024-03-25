use actix_web::{cookie::Key, App, HttpServer, HttpResponse};
use actix_identity::IdentityMiddleware;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{get, post, Responder, HttpRequest, HttpMessage};
use actix_identity::Identity;

#[get("/")]
async fn index(user: Option<Identity>) -> impl Responder {
    if let Some(user) = user {
        format!("Welcome! {}", user.id().unwrap())
    } else {
        "Welcome Anonymous!".to_owned()
    }
}

#[get("/login")]
async fn login(request: HttpRequest) -> impl Responder {
    // Some kind of authentication should happen here
    // e.g. password-based, biometric, etc.
    // [...]

    // attach a verified user identity to the active session
    Identity::login(&request.extensions(), "User1".into()).unwrap();

    HttpResponse::Ok()
}

#[get("/logout")]
async fn logout(user: Identity) -> impl Responder {
    user.logout();
    HttpResponse::Ok()
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
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}