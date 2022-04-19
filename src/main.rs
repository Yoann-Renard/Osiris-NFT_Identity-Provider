#[macro_use]
extern crate validator_derive;


mod config;
mod db;
mod errors;
mod handlers;
mod models;
use handlers::app_config;


extern crate serde;
use crate::config::Config;
//use chrono::{DateTime, Utc};
use actix_web::{web, App, HttpServer, Responder, middleware::Logger ,HttpResponse};
use serde::{Deserialize, Serialize};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};


#[derive(Serialize, Deserialize)]
pub struct Response {
    result: String
}

#[derive(Debug,Serialize, Deserialize)]
struct LoginUser {
    username: String,
    password: String,
    id : String,

}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputUser {
    pub fname: String,
    pub lname: String,
    pub email: String,
    pub pwd : String,
}
#[derive(Debug)]
pub struct NewUser<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub pass_word: &'a str,
    pub email: &'a str,
    pub created_at: chrono::NaiveDateTime,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Inputlogin {
    pub email: String,
    pub pwd : String,
}

 #[actix_web::main]
 async fn main() -> std::io::Result<()> {


    //config
        let config : Config= Config::from_env()
            .expect("error while server configuration");

    //pool (allow connection to be reuse for futures requests)

    let pool = config.db_pool().await.expect("pool error");

    //init the crypto service 

    let crypto_service = config.crypto_service();

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();

     HttpServer::new( move || {
         App::new()
                .wrap(Logger::default())
                .data(pool.clone())
                .data(crypto_service.clone())
                .configure(app_config)
                //.route("/signin", web::post().to(signin))
                // .route("/login", web::post().to(login))
                 //.route("/addition2", web::post().to(addition))
                 //  .servic e(
                 //     web::resource("/addition2").route(
                 //         web::post().to(addition2)))
     })         
     .bind_openssl("127.0.0.1:8080", builder)?
     //.bind(format!("{}:{}",config.host,config.port))?
     .run()
     .await
 }

 //https://codepen.io/eridio/pen/BawLmBb
 //https://codepen.io/onediv/pen/WNOdMWw



// oceane veut parler a lethithia
// un quitte la com --> les messages sont transmis au serv
// si le serv est pas la --> la peer to perr continue la discution
// et si  un utilisateur se deco -> message perdu


//postgresql ok 
//inclure

//https://github.com/nemesiscodex/user-auth