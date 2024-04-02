use actix_identity::IdentityMiddleware;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{App, HttpServer};
use rusqlite::Connection;

mod account_data;
mod account_endpoints;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let secret_key = account_data::key_handle();
    let conn = Connection::open("accounts.db").unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
             username TEXT PRIMARY KEY,
             password TEXT)",
        [],
    )
    .unwrap();
    HttpServer::new(move || {
        App::new()
            .wrap(IdentityMiddleware::default())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone(),
            ))
            .service(account_endpoints::index)
            .service(account_endpoints::login)
            .service(account_endpoints::logout)
            .service(account_endpoints::do_login)
            .service(account_endpoints::create_account)
            .service(account_endpoints::do_create_account)
            .service(account_endpoints::login_message)
            .service(account_endpoints::create_account_message)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
