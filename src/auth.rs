use actix_web::{get, web::ServiceConfig};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AuthToken;

pub(super) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config 
            .service(auth);
    }
}


#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct SignedMessage {
    pub message: String,
    pub signature: String,
    pub public_key: String,
}


/// Authentication endpoint
///
/// Authenticate user
///
#[utoipa::path(
    responses(
        (status = 200, description = "Authenticate user", body = SignedMessage)
    ),
    security(
        ("bearerAuth" = [])
    )
)]
#[get("/auth", wrap = "AuthToken")]
// Handler for validating signatures
pub(super) async fn auth() -> String {
    //Return the string "Authenticated"
    "Authenticated".to_string()
}
