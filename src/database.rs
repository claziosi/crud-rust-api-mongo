use actix_web::{
    delete, get, post, put,
    web::{self, Data, Json, Path, ServiceConfig},
    HttpResponse, Responder,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use utoipa::{ToSchema, IntoParams};
use serde_json::Value;
use mongodb::{
    bson::{self, doc, oid::ObjectId, Document}, Collection, Database
};


use crate::{LogApiKey, RequireApiKey};


pub(super) fn configure(db: Data<Database>) -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config
            .app_data(db)
            .service(search)
            .service(get_all)
            .service(create)
            .service(delete)
            .service(get_by_id)
            .service(update);
    }
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
#[get("/get/{collection_name}")]
pub(super) async fn get_all(path: web::Path<String>, db: web::Data<Database>) -> impl Responder {
    let collection_name = path.into_inner();
    let collection:Collection<Document> = db.collection(&collection_name);

    match collection.find(None, None).await {
        Ok(mut cursor) => {
            let mut results = Vec::new();
            while let Some(result) = cursor.next().await {
                match result {
                    Ok(document) => results.push(document),
                    Err(e) => return HttpResponse::InternalServerError().json(e.to_string()),
                }
            }
            
            // Convert BSON documents into JSON Value format
            let json_results: serde_json::Value = match bson::to_bson(&results) {
                Ok(bson) => match bson {
                    bson::Bson::Array(bson_array) => serde_json::to_value(bson_array).unwrap_or_default(),
                    _ => serde_json::Value::Array(vec![]),
                },
                Err(_) => serde_json::Value::Array(vec![]),
            };
            
            HttpResponse::Ok().json(json_results)
        },
        Err(e) => {
            eprintln!("Failed to fetch documents: {}", e);
            HttpResponse::InternalServerError().json(e.to_string())
        }
    }
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

#[post("/add/{collection_name}")]
pub(super) async fn create(
    path: web::Path<String>,
    object: Json<Value>,
    db: web::Data<Database>,
) -> impl Responder {
    let object = object.into_inner();
    let collection_name = path.into_inner();
    let collection: Collection<Document> = db.collection(&collection_name);

    match object {
        // If it's an array, we'll use insert_many
        Value::Array(array) => {
            // Convert each JSON Value into BSON document
            let documents: Vec<Document> = array.into_iter()
                .filter_map(|item| bson::to_bson(&item).ok())
                .filter_map(|bson| match bson {
                    bson::Bson::Document(document) => Some(document),
                    _ => None,
                })
                .collect();

            // Insert many documents
            match collection.insert_many(documents, None).await {
                Ok(insert_result) => HttpResponse::Created().json(insert_result.inserted_ids),
                Err(e) => {
                    eprintln!("Failed to insert documents: {}", e);
                    HttpResponse::InternalServerError().json(e.to_string())
                }
            }
        },
        // If it's not an array, assume it's a single document and use insert_one
        _ => {
            // Convert JSON Value into BSON document
            let document = match bson::to_bson(&object) {
                Ok(bson) => match bson {
                    bson::Bson::Document(document) => document,
                    _ => return HttpResponse::BadRequest().body("Invalid BSON format"),
                },
                Err(_) => return HttpResponse::InternalServerError().body("Failed to convert to BSON"),
            };

            // Insert one document
            match collection.insert_one(document.clone(), None).await {  // Clone needed because we move `document` here.
                Ok(_) => HttpResponse::Created().json(object),
                Err(e) => {
                    eprintln!("Failed to insert document: {}", e);
                    HttpResponse::InternalServerError().json(e.to_string())
                }
            }
        }
    }
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

#[delete("/delete/{collection_name}/{id}")]
pub(super) async fn delete(
    path: web::Path<(String, String)>, // Change id extraction to String
    db: web::Data<Database>,
) -> impl Responder {
    
    let (collection_name, id_str) = path.into_inner(); // Extract id as String

    let collection: Collection<Document> = db.collection(&collection_name);
    
    println!("collection_name: {}", collection_name);

    // Convert the string representation of ObjectId into an actual ObjectId
    let object_id = match ObjectId::parse_str(&id_str) {
        Ok(oid) => oid,
        Err(e) => {
            eprintln!("Invalid ObjectId format: {}", e);
            return HttpResponse::BadRequest().json(format!("Invalid ObjectId format"));
        }
    };

    // Remove the object from the collection by _id
    match collection.delete_one(doc! { "_id": object_id }, None).await {
        Ok(delete_result) => {
            if delete_result.deleted_count > 0 {
                HttpResponse::Ok().json(format!("Document _id = {} successfully removed", id_str))
            } else {
                HttpResponse::NotFound().json(format!("_id = {}", id_str))
            }
        },
        Err(e) => {
            eprintln!("Failed to delete document with _id {}: {}", id_str, e);
            HttpResponse::InternalServerError().json(e.to_string())
        }
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
#[get("/get/{collection_name}/{id}")]
pub(super) async fn get_by_id(path: web::Path<(String, String)>, // Change id extraction to String
db: web::Data<Database>) -> impl Responder {
    
    let (collection_name, id_str) = path.into_inner(); // Extract id as String

    let collection: Collection<Document> = db.collection(&collection_name);
    
    println!("collection_name: {}", collection_name);

    // Convert the string representation of ObjectId into an actual ObjectId
    let object_id = match ObjectId::parse_str(&id_str) {
        Ok(oid) => oid,
        Err(e) => {
            eprintln!("Invalid ObjectId format: {}", e);
            return HttpResponse::BadRequest().json(format!("Invalid ObjectId format"));
        }
    };

    // Find the object from the collection by _id
    match collection.find_one(doc! { "_id": object_id }, None).await {
        Ok(Some(document)) => {
            HttpResponse::Ok().json(document)
        },
        Ok(None) => {
            HttpResponse::NotFound().json(format!("_id = {}", id_str))
        },
        Err(e) => {
            eprintln!("Failed to find document with _id {}: {}", id_str, e);
            HttpResponse::InternalServerError().json(e.to_string())
        }
    }

}

/// Update Object with given id.
///
/// This endpoint supports optional authentication.
///
/// Tries to update `Object` by given id as path variable. If object is found by id values are
/// updated according `ObjectUpdateRequest` and updated `Object` is returned with status 200.
/// If object is not found then 404 not found is returned.
#[utoipa::path(
    request_body = JsonObject,
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
) -> impl Responder {
    let id = id.into_inner();

    HttpResponse::Created().json(id)
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
) -> impl Responder {
    
    HttpResponse::Created().json("id")
}