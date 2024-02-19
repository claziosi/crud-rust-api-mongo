use std::{
    error::Error,
    future::{self, Ready},
    net::Ipv4Addr,
};

use actix_cors::Cors;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform}, http, middleware::Logger, web::Data, App, HttpResponse, HttpServer
};
use base64::{engine::general_purpose, Engine};
use futures::future::LocalBoxFuture;
use mongodb::{options::ClientOptions, Client};
use openssl::{bn::BigNumContext, ec::{EcGroup, EcKey, EcPoint}, nid::Nid, pkey::PKey, sign::Verifier};
// use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use utoipa::{
    openapi::security::{Http, HttpAuthScheme, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::{Redoc, Servable};
use utoipa_swagger_ui::SwaggerUi;

use crate::database::ErrorResponse;

mod database;
mod auth;

// You would typically put this in your application state.
async fn create_mongo_client(uri: &str) -> Result<Client, mongodb::error::Error> {
    let client_options = ClientOptions::parse(uri).await?;
    Client::with_options(client_options)
}


#[actix_web::main]
async fn main() -> Result<(), impl Error> {
    env_logger::init();

    #[derive(OpenApi)]
    #[openapi(
        paths(
            database::get_all,
            database::create,
            database::delete,
            database::get_by_id,
            database::update,
            database::get_by_key_value,
            auth::auth
        ),
        components(
            schemas(database::ErrorResponse),
            schemas(auth::SignedMessage)
        ),
        tags(
            (name = "database", description = "Database management endpoints."),
            (name = "auth", description = "Authentication endpoints.")
        ),
        modifiers(&SecurityAddon)
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components: &mut utoipa::openapi::Components = openapi.components.as_mut().unwrap(); // we can unwrap safely since there already is components registered.
            components.add_security_scheme(
                "bearerAuth",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            )
        }
    }

    // Set up the SSL builder.
    /* let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("/etc/letsencrypt/live/salvr.westeurope.cloudapp.azure.com/privkey.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("/etc/letsencrypt/live/salvr.westeurope.cloudapp.azure.com/fullchain.pem").unwrap(); */

    let mongo_client = Data::new(create_mongo_client("mongodb://localhost:27017").await.unwrap());
    let db = Data::new(mongo_client.database("salvr"));

    // Make instance variable of ApiDoc so all worker threads gets the same instance.
    let openapi = ApiDoc::openapi();

    HttpServer::new(move || {
        // Add CORS support
        let cors = Cors::default()
            .allowed_origin("localhost:3000") // Allow only http://localhost as origin
            .allowed_methods(vec!["GET", "POST", "UPDATE", "DELETE"]) // Specify allowed methods
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600); // Set max age for preflight cache

        // This factory closure is called on each worker thread independently.
        App::new()
            .wrap(cors)
            .wrap(Cors::permissive())   // Apply CORS middleware to all routes but comment this line for PRODUCTION !!
            .wrap(Logger::default())
            .configure(database::configure(db.clone()))
            .configure(auth::configure())
            .service(Redoc::with_url("/redoc", openapi.clone()))
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
            )
            // There is no need to create RapiDoc::with_openapi because the OpenApi is served
            // via SwaggerUi instead we only make rapidoc to point to the existing doc.
            .service(RapiDoc::new("/api-docs/openapi.json").path("/rapidoc"))
            // Alternative to above
            // .service(RapiDoc::with_openapi("/api-docs/openapi2.json", openapi.clone()).path("/rapidoc"))
    })
    // .bind_openssl("0.0.0.0:443", builder)?
    .bind((Ipv4Addr::UNSPECIFIED, 8080))?
    .run()
    .await
}

/// Log api key middleware only logs about missing or invalid api keys
struct AuthToken;

impl<S> Transform<S, ServiceRequest> for AuthToken
where
    S: Service<
        ServiceRequest,
        Response = ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
{
    type Response = ServiceResponse<actix_web::body::BoxBody>;
    type Error = actix_web::Error;
    type Transform = AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(AuthMiddleware {
            service,
        }))
    }
}

struct AuthMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<
        ServiceRequest,
        Response = ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
{
    type Response = ServiceResponse<actix_web::body::BoxBody>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, actix_web::Error>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {

        let response = |req: ServiceRequest, response: HttpResponse| -> Self::Future {
            Box::pin(async { Ok(req.into_response(response)) })
        };

        println!("Request: {:?}", req);
        // Check if the signature is valid 
        // Get the token from the request Authorization base64 header and decode it
        // manage if the token is empty or invalid
        let authorization_header = match req.headers().get("Authorization") {
            Some(header) => header,
            None => {
                return response(
                    req,
                    HttpResponse::Unauthorized()
                        .json(ErrorResponse::Unauthorized(String::from("Missing Token"))),
                );
            }
        };
        
        //replace "Bearer " with "" to get the token
        let authorization_header = authorization_header.to_str().unwrap().replace("Bearer ", "");

        // Decode the base64token to a string
        let base64_token = authorization_header;
        let token_bytes =  match general_purpose::STANDARD.decode(base64_token) {
            Ok(token) => token,
            Err(_) => {
                return response(
                    req,
                    HttpResponse::Unauthorized()
                        .json(ErrorResponse::Unauthorized(String::from("Malformed/Invalid Token"))),
                );
            }
        };
        
        let token = String::from_utf8(token_bytes).unwrap();

        let public_key = token.split(":").collect::<Vec<&str>>()[0];
        let signature = token.split(":").collect::<Vec<&str>>()[1];
        let message = token.split(":").collect::<Vec<&str>>()[2];

        // Nonce to prevent replay attacks (to be sent to the client on a regular basis)
        // Change the nonce will prevent the reuse of the same signature twice
        let nonce = "30450221009137c8489f844822843868d77f93c288ea64427005".as_bytes().to_vec();

        // Convert hexadecimal strings to byte slices
        let public_key_bytes = hex::decode(&public_key).unwrap();
        let signature_bytes = hex::decode(&signature).unwrap();


        // Initialize a BigNumContext
        let mut ctx = BigNumContext::new().unwrap();

        // Create an EC key directly from the public key bytes
        let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let ec_point = EcPoint::from_bytes(&group, &public_key_bytes, &mut ctx).unwrap();
        let ec_key = EcKey::from_public_key(&group, &ec_point).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();

        // Initialize a verifier
        let mut verifier = Verifier::new_without_digest(&pkey).unwrap();

        // Convert the message to a byte slice
        let mut msg = message.bytes().collect::<Vec<u8>>();

        // Concatenate msg and once
        msg.extend_from_slice(&nonce);

        let result = verifier.verify_oneshot(&signature_bytes, &msg).unwrap();

        if result {
            // If the signature is valid, call the next middleware
            let future = self.service.call(req);

            Box::pin(async move {
                let response = future.await?;
                Ok(response)
            })
        } else {
            // If the signature is invalid, return an error
            return response(
                req,
                HttpResponse::Unauthorized()
                    .json(ErrorResponse::Unauthorized(String::from("Invalid Token"))),
            );
        }
        

    }
}