use std::{
    error::Error,
    future::{self, Ready},
    net::Ipv4Addr,
};

use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    middleware::Logger,
    web::Data,
    App, HttpResponse, HttpServer,
};
use futures::future::LocalBoxFuture;
use mongodb::{options::ClientOptions, Client};
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::{Redoc, Servable};
use utoipa_swagger_ui::SwaggerUi;

use crate::database::ErrorResponse;

mod database;

const API_KEY_NAME: &str = "apikey";
const API_KEY: &str = "utoipa-rocks";

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
            database::search
        ),
        components(
            schemas(database::JsonObject, database::JsonObject, database::ErrorResponse)
        ),
        tags(
            (name = "database", description = "Database management endpoints.")
        ),
        modifiers(&SecurityAddon)
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components = openapi.components.as_mut().unwrap(); // we can unwrap safely since there already is components registered.
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("apikey"))),
            )
        }
    }

    let mongo_client = Data::new(create_mongo_client("mongodb://localhost:27017").await.unwrap());
    let db = Data::new(mongo_client.database("mydb"));

    // Make instance variable of ApiDoc so all worker threads gets the same instance.
    let openapi = ApiDoc::openapi();

    HttpServer::new(move || {
        // This factory closure is called on each worker thread independently.
        App::new()
            .wrap(Logger::default())
            .configure(database::configure(db.clone()))
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
    .bind((Ipv4Addr::UNSPECIFIED, 8080))?
    .run()
    .await
}

/// Require api key middleware will actually require valid api key
struct RequireApiKey;

impl<S> Transform<S, ServiceRequest> for RequireApiKey
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
    type Transform = ApiKeyMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(ApiKeyMiddleware {
            service,
            log_only: false,
        }))
    }
}

/// Log api key middleware only logs about missing or invalid api keys
struct LogApiKey;

impl<S> Transform<S, ServiceRequest> for LogApiKey
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
    type Transform = ApiKeyMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(ApiKeyMiddleware {
            service,
            log_only: true,
        }))
    }
}

struct ApiKeyMiddleware<S> {
    service: S,
    log_only: bool,
}

impl<S> Service<ServiceRequest> for ApiKeyMiddleware<S>
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

        match req.headers().get(API_KEY_NAME) {
            Some(key) if key != API_KEY => {
                if self.log_only {
                    log::debug!("Incorrect api api provided!!!")
                } else {
                    return response(
                        req,
                        HttpResponse::Unauthorized().json(ErrorResponse::Unauthorized(
                            String::from("incorrect api key"),
                        )),
                    );
                }
            }
            None => {
                if self.log_only {
                    log::debug!("Missing api key!!!")
                } else {
                    return response(
                        req,
                        HttpResponse::Unauthorized()
                            .json(ErrorResponse::Unauthorized(String::from("missing api key"))),
                    );
                }
            }
            _ => (), // just passthrough
        }

        if self.log_only {
            log::debug!("Performing operation")
        }

        let future = self.service.call(req);

        Box::pin(async move {
            let response = future.await?;

            Ok(response)
        })
    }
}