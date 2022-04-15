use super::AppResponse;
use crate::{
    config::crypto::{Auth, CryptoService},
    db::user::UserRepository,
    errors::{AppErrorCode,AppError},
};
use actix_web::cookie::Cookie;
use actix_web::{web::Data,web::Form, FromRequest, HttpResponse, HttpRequest,dev::HttpResponseBuilder,web::Json};
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


        //if cookie -> ok {
            // display 
        //}
        //value du COOKIE WOW:
        //let c = Cookie::parse(req.headers().get("cookie").unwrap().to_str().unwrap());
        //let c_result = c.clone();
        //let c_value = Cookie::parse(req.headers().get("cookie").unwrap().to_str().unwrap()).unwrap().value();
       // println!("cookie value : {:?}", c.unwrap().value());


        //println!("basic : {:?}", basic);
        let username = &basic.username;
        //println!("{}", username);
        let password = &basic.password;
        
        //println!("from signin : {}", password);
        let user = repository.find_by_username(username).await.expect("error");
                            //  .await?
                            //  .ok_or_else(|| {
                            //     debug!("user do not exist");
                            //     AppError::INVALID_CREDENTIALS
                            //  })?;

        let valid = hashing.verify_password(password, &user.password_hash).await;

        
        if valid {                
                            let token = hashing.generate_jwt(user.id).await.expect("err");
                            println!("{:?}",token);
                            let cookie = Cookie::new("JWT", &token);
                            println!("{}",&cookie);
                            // Ok(HttpResponse::Ok()  
                            //                     .cookie(Cookie::build("JWT", &token).finish())
                            //                     .header("Location", "/app")
                            //                     .json(Auth{token }))
                            //Cookie::build("JWT", &token).domain("localhost").finish()
                            
                            
                            // println!("request to send = {:#?}",HttpResponse::Found()
                            //                                         .header("Location", "https://127.0.0.1:4201/app")
                            //                                         .cookie(Cookie::build("JWT", &token) 
                            //                                         // .secure(true)
                            //                                         // .http_only(true)     
                            //                                                     // .domain("http://localhost:4201")
                            //                                                     // .path("/app")
                            //                                                     .finish()));
                            Ok(HttpResponse::Found()
                                                    .header("Location", "https://127.0.0.1:4201/app")
                                                    .cookie(Cookie::build("JWT", &token) 
                                                     .secure(true)
                                                     .http_only(true)       
                                                                // .domain("http://localhost:4201")
                                                                // .path("/app")
                                                                .finish())
                                                    .json(Auth{token})
                                                
                                                )

                            
                        }

                        else {
                            Err(HttpResponse::Found().header("Location", "https://127.0.0.1:4201/").finish())
                            //Err(AppError::INVALID_CREDENTIALS.into())
                        }
                    
                   
    }