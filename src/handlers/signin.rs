use super::AppResponse;
use super::{authentication::AuthenticatedUser, authentication::CookieJWT};
use crate::{
    config::crypto::{Auth, CryptoService},
    db::user::UserRepository,
    errors::{AppErrorCode,AppError},
};
use actix_web::cookie::Cookie;
use actix_web::{web::Payload,web::Data,web::Form, FromRequest, HttpResponse, HttpRequest,dev::HttpResponseBuilder,web::Json,get,HttpMessage};
use actix_web_httpauth::extractors::{basic::BasicAuth, bearer::BearerAuth};
use futures::future::{ready, BoxFuture};
use tracing::{debug, instrument};
use uuid::Uuid;
use serde::{Deserialize,Serialize};


#[derive(Debug,Deserialize,Serialize)]
pub struct Inputlogin {
    pub username:String,
    pub password:String,
}




#[instrument(skip(basic, repository, hashing))]
pub async fn signin(
    basic : Form<Inputlogin>,
    repository : UserRepository,
    hashing: Data<CryptoService>,
    req: HttpRequest) -> Result<actix_web::HttpResponse,actix_web::HttpResponse> {

        let username = &basic.username;
        //println!("{}", username);
        let password = &basic.password;
        
        //println!("from signin : {}", password);
        let user = repository.find_by_username(username).await.expect("error");
                      

        let valid = hashing.verify_password(password, &user.password_hash).await;

        
        if valid {                
                            let token = hashing.generate_jwt(user.id).await.expect("err");
                            println!("{:?}",token);
                            let cookie = Cookie::new("JWT", &token);
                            println!("{}",&cookie);
                                                              
                            Ok(HttpResponse::Found()
                                                    .header("Location", "https://yoloooo.com")
                                                    .cookie(Cookie::build("JWT", &token) 
                                                    .secure(true)
                                                    .http_only(true)       
                                                    .finish())
                                                    .finish()
                                                
                                                )
                        }
                        else {
                            Err(HttpResponse::Found().header("Location", "https://yoloooo.com/front").finish())
                            //Err(AppError::INVALID_CREDENTIALS.into())
                        }              
    }

pub async fn verify_authent( req: actix_web::HttpRequest, mut payload: actix_web::web::Payload,repository : UserRepository, hashing: Data<CryptoService>) -> HttpResponse {
  
    //into_inner() -> conv between  actix_web::web::Payload and  actix_web::dev::Payload
    let cookie = CookieJWT::from_request(&req,&mut payload.into_inner()).into_inner();
    let auth_result = hashing.verify_jwt(cookie.unwrap().cookie_value).await;
    match auth_result{
        Ok(v) => HttpResponse::Ok().finish(),
        _ => HttpResponse::Found().header("Location", "https://yolooo.com/").finish(),
    }
}