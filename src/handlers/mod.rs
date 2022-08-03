use actix_web::{web, web::ServiceConfig, HttpResponse};
mod signin;
mod authentication;
use crate::errors::AppError;

use signin::{signin,verify_authent};

type AppResult<T> = Result<T, AppError>;
type AppResponse = AppResult<HttpResponse>;


pub fn app_config(config : &mut ServiceConfig) {

    let signin = web::resource("/signin").route(web::post().to(signin));
    let verify_authent = web::resource("/verify_auth").route(web::get().to(verify_authent));
    config.service(signin).service(verify_authent);
}