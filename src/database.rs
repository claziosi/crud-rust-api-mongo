use std::sync::Mutex;

use actix_web::{
    delete, get, post, put,
    web::{Data, Json, Path, Query, ServiceConfig},
    HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use utoipa::{ToSchema, IntoParams};

use crate::{LogApiKey, RequireApiKey};

#[derive(Default)]
pub(super) struct DatabaseStore {
    objects: Mutex<Vec<JsonObject>>,
}

pub(super) fn configure(store: Data<DatabaseStore>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config
            .app_data(store)
            .service(search)
            .service(get_all)
            .service(create)
            .service(delete)
            .service(get_by_id)
            .service(update);
    }
}

/// Task to do.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
pub(super) struct JsonObject {
    /// Unique id for the object item.
    #[schema(example = 1)]
    id: i32,
    /// Description of the tasks to do.
    #[schema(example = "Remember to buy groceries")]
    value: String,
    /// Mark is the task done or not
    checked: bool,
}


/// Object endpoint error responses
#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub(super) enum ErrorResponse {
    /// When Object is not found by search term.
    NotFound(String),
    /// When there is a conflict storing a new object.
    Conflict(String),
    /// When object endpoint was called without correct credentials
    Unauthorized(String),
}

/// Get list of objects.
///
/// List objects from in-memory object store.
///
/// One could call the api endpoint with following curl.
/// ```text
/// curl localhost:8080/object
/// ```
#[utoipa::path(
    responses(
        (status = 200, description = "List current object items in the collection_anem", body = [Object])
    )
)]
#[get("/getall")]
pub(super) async fn get_all(object_store: Data<DatabaseStore>) -> impl Responder {
    let objects = object_store.objects.lock().unwrap();

    HttpResponse::Ok().json(objects.clone())
}

/// Create new Object to shared in-memory storage.
///
/// Post a new `Object` in request body as json to store it. Api will return
/// created `Object` on success or `ErrorResponse::Conflict` if object with same id already exists.
///
/// One could call the api with.
/// ```text
/// curl localhost:8080/object -d '{"id": 1, "value": "Buy movie ticket", "checked": false}'
/// ```
#[utoipa::path(
    request_body = Object,
    responses(
        (status = 201, description = "Object created successfully in the collection_name", body = JsonObject),
        (status = 409, description = "Object with id already exists in the collection_name", body = ErrorResponse, example = json!(ErrorResponse::Conflict(String::from("id = 1"))))
    )
)]
#[post("/create")]
pub(super) async fn create(object: Json<JsonObject>, object_store: Data<DatabaseStore>) -> impl Responder {
    let mut objects = object_store.objects.lock().unwrap();
    let object = &object.into_inner();

    objects
        .iter()
        .find(|existing| existing.id == object.id)
        .map(|existing| {
            HttpResponse::Conflict().json(ErrorResponse::Conflict(format!("id = {}", existing.id)))
        })
        .unwrap_or_else(|| {
            objects.push(object.clone());

            HttpResponse::Ok().json(object)
        })
}

/// Delete Object by given path variable id.
///
/// This endpoint needs `api_key` authentication in order to call. Api key can be found from README.md.
///
/// Api will delete object from shared in-memory storage by the provided id and return success 200.
/// If storage does not contain `Object` with given id 404 not found will be returned.
#[utoipa::path(
    responses(
        (status = 200, description = "Object deleted successfully in the collection_name"),
        (status = 401, description = "Unauthorized to delete Object", body = ErrorResponse, example = json!(ErrorResponse::Unauthorized(String::from("missing api key")))),
        (status = 404, description = "Object not found by id in the collection_name", body = ErrorResponse, example = json!(ErrorResponse::NotFound(String::from("id = 1"))))
    ),
    params(
        ("id", description = "Unique storage id of Object")
    ),
    security(
        ("api_key" = [])
    )
)]
#[delete("/delete/{id}", wrap = "RequireApiKey")]
pub(super) async fn delete(id: Path<i32>, object_store: Data<DatabaseStore>) -> impl Responder {
    let mut objects = object_store.objects.lock().unwrap();
    let id = id.into_inner();

    let new_objects = objects
        .iter()
        .filter(|object| object.id != id)
        .cloned()
        .collect::<Vec<_>>();

    if new_objects.len() == objects.len() {
        HttpResponse::NotFound().json(ErrorResponse::NotFound(format!("id = {id}")))
    } else {
        *objects = new_objects;
        HttpResponse::Ok().finish()
    }
}

/// Get Object by given object id.
///
/// Return found `Object` with status 200 or 404 not found if `Object` is not found from shared in-memory storage.
#[utoipa::path(
    responses(
        (status = 200, description = "Object found from storage", body = Object),
        (status = 404, description = "Object not found by id in the collection_name", body = ErrorResponse, example = json!(ErrorResponse::NotFound(String::from("id = 1"))))
    ),
    params(
        ("id", description = "Unique storage id of Object")
    )
)]
#[get("/get/{id}")]
pub(super) async fn get_by_id(id: Path<i32>, object_store: Data<DatabaseStore>) -> impl Responder {
    let objects = object_store.objects.lock().unwrap();
    let id = id.into_inner();

    objects
        .iter()
        .find(|object| object.id == id)
        .map(|object| HttpResponse::Ok().json(object))
        .unwrap_or_else(|| {
            HttpResponse::NotFound().json(ErrorResponse::NotFound(format!("id = {id}")))
        })
}

/// Update Object with given id.
///
/// This endpoint supports optional authentication.
///
/// Tries to update `Object` by given id as path variable. If object is found by id values are
/// updated according `ObjectUpdateRequest` and updated `Object` is returned with status 200.
/// If object is not found then 404 not found is returned.
#[utoipa::path(
    request_body = ObjectUpdateRequest,
    responses(
        (status = 200, description = "Object updated successfully in the collection_name", body = Object),
        (status = 404, description = "Object not found by id in the collection_name", body = ErrorResponse, example = json!(ErrorResponse::NotFound(String::from("id = 1"))))
    ),
    params(
        ("id", description = "Unique storage id of Object")
    ),
    security(
        (),
        ("api_key" = [])
    )
)]
#[put("/update/{id}", wrap = "LogApiKey")]
pub(super) async fn update(
    id: Path<i32>,
    object: Json<JsonObject>,
    object_store: Data<DatabaseStore>,
) -> impl Responder {
    let mut objects = object_store.objects.lock().unwrap();
    let id = id.into_inner();
    let object = &object.into_inner();

    let new_objects = objects
        .iter()
        .map(|existing| {
            if existing.id == id {
                object.clone()
            } else {
                existing.clone()
            }
        })
        .collect::<Vec<_>>();

    if new_objects.len() == objects.len() {
        HttpResponse::NotFound().json(ErrorResponse::NotFound(format!("id = {id}")))
    } else {
        *objects = new_objects;
        HttpResponse::Ok().json(object)
    }
}

/// Search objects Query
#[derive(Deserialize, Debug, IntoParams)]
pub(super) struct SearchObjects {
    /// Content that should be found from Object's value field
    value: String,
}

/// Search Objects with by value
///
/// Perform search from `Object`s present in in-memory storage by matching Object's value to
/// value provided as query parameter. Returns 200 and matching `Object` items.
#[utoipa::path(
    params(
        SearchObjects
    ),
    responses(
        (status = 200, description = "Search Objects did not result error", body = [Object]),
    )
)]
#[get("/search")]
pub(super) async fn search(
    query: Query<SearchObjects>,
    object_store: Data<DatabaseStore>,
) -> impl Responder {
    let objects = object_store.objects.lock().unwrap();

    HttpResponse::Ok().json(
        objects
            .iter()
            .filter(|object| {
                object.value
                    .to_lowercase()
                    .contains(&query.value.to_lowercase())
            })
            .cloned()
            .collect::<Vec<_>>(),
    )
}