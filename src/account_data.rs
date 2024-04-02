use actix_web::cookie::Key;
use rusqlite::{Connection, Result};
use std::io::Write;

pub fn key_handle() -> Key {
    if std::path::Path::new("/etc/hosts").exists() {
        let text = std::fs::read_to_string("key.pbkdf2").unwrap();
        Key::from(text.as_bytes())
    } else {
        let key = Key::generate();
        let file = std::fs::File::options()
            .create(true)
            .write(true)
            .open("key.pbkdf2");
        let _ = file.unwrap().write_all(key.master());
        key
    }
}

pub fn insert_user_sqlite(username: String, password: String) -> Result<()> {
    let mut conn = Connection::open("accounts.db")?;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO users (username, password) VALUES (?1, ?2)",
        [&username, &password],
    )?;
    tx.commit()?;
    Ok(())
}

pub struct UserInfo {
    pub _username: String,
    pub password: String,
}

pub fn get_user_info_sqlite(username: String) -> Option<UserInfo> {
    let conn = Connection::open("accounts.db").unwrap();
    let mut stmt = conn
        .prepare("SELECT * FROM users WHERE username = ?1")
        .unwrap();
    let mut rows = stmt.query([&username]).unwrap();
    if let Some(row) = rows.next().unwrap() {
        //let username: String = row.get(0).unwrap();
        let password: String = row.get(1).unwrap();
        Some(UserInfo {
            _username: username,
            password,
        })
    } else {
        None
    }
}