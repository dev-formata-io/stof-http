//
// Copyright 2024 Formata, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};
use anyhow::{anyhow, Result};
use axum::{body::{Body, Bytes}, extract::{Path, Query, State}, http::{header::CONTENT_TYPE, HeaderMap, HeaderName, Method, StatusCode}, response::{IntoResponse, Response}, routing::get, Router};
use stof::{IntoDataRef, SData, SDataRef, SDoc, SField, SFunc, SVal, FUNC_KIND};
use tokio::sync::Mutex;
use tower_governor::{governor::GovernorConfig, GovernorLayer};
use tower_http::cors::CorsLayer;


/// Serve a Stof document.
/// This is the entrypoint for starting a Stof HTTP server.
pub fn serve(doc: SDoc) {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            internal_serve(doc).await;
        });
}

/// Server state.
#[derive(Clone)]
pub struct ServerState {
    pub doc: Arc<Mutex<SDoc>>,
    pub opaque_errors: bool,
    pub get_handlers: Arc<BTreeMap<String, SDataRef>>,
    pub put_handlers: Arc<BTreeMap<String, SDataRef>>,
    pub post_handlers: Arc<BTreeMap<String, SDataRef>>,
    pub delete_handlers: Arc<BTreeMap<String, SDataRef>>,
    pub head_handlers: Arc<BTreeMap<String, SDataRef>>,
    pub patch_handlers: Arc<BTreeMap<String, SDataRef>>,
}
impl ServerState {
    pub fn handler(&self, method: Method, path: &str) -> Result<SDataRef> {
        let handlers;
        match method {
            Method::PUT => handlers = self.put_handlers.clone(),
            Method::DELETE => handlers = self.delete_handlers.clone(),
            Method::PATCH => handlers = self.patch_handlers.clone(),
            Method::POST => handlers = self.post_handlers.clone(),
            Method::HEAD => handlers = self.head_handlers.clone(),
            _ => handlers = self.get_handlers.clone(),
        }
        if let Some(value) = handlers.get(path) {
            return Ok(value.clone());
        }
        // TODO: wildcards and path based stuff....
        Err(anyhow!(""))
    }
}

/// Internal serve.
async fn internal_serve(mut doc: SDoc) {
    // Get configuration data from the document (doc acts as it's own config...)
    // All info should be in the root Server object - this will get removed before the document is served (security)

    // Server address is in "Server.Config.Address"
    // root Server: { Config: { Address: { ip: '127.0.0.1', port: 3030 } } }
    let mut ip = [127, 0, 0, 1];
    let mut port = 3030;
    if let Some(ip_field) = SField::field(&doc.graph, "Server.Config.Address.ip", '.', None) {
        let string = ip_field.to_string();
        let path = string.split('.').collect::<Vec<&str>>();
        if path.len() == 4 {
            for i in 0..4 {
                let val: Result<u8, _> = path[i].parse();
                match val {
                    Ok(v) => {
                        ip[i] = v;
                    },
                    Err(_) => {
                        ip = [127, 0, 0, 1];
                        println!("Error starting server at the requested IP: {}, using 127.0.0.1 instead...", string);
                        break;
                    }
                }
            }
        }
    }
    if let Some(port_field) = SField::field(&doc.graph, "Server.Config.Address.port", '.', None) {
        let val: Result<u16, _> = port_field.to_string().parse();
        match val {
            Ok(v) => {
                port = v;
            },
            Err(_) => {
                println!("Error listening on port {}, using port 3030 instead...", port_field.to_string());
            }
        }
    }
    let address = SocketAddr::from((ip, port));

    // Opaque errors - determin whether stof should expose the internal server errors as responses... default is true to prevent leaking internal info..
    // can be helpful for debugging, etc.
    let mut opaque_server_errors = true;
    if let Some(opaque_field) = SField::field(&doc.graph, "Server.Config.opaque_errors", '.', None) {
        opaque_server_errors = opaque_field.value.truthy();
    }

    // Setup governor configuration - see https://crates.io/crates/tower_governor
    let governor_conf = Arc::new(GovernorConfig::default());

    // Spawn a separate background task to cleanup governor
    let governor_limiter = governor_conf.limiter().clone();
    let interval = Duration::from_secs(60);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            governor_limiter.retain_recent();
        }
    });

    // Cors layer
    let cors = CorsLayer::permissive();

    // Create a new server state with the document
    if let Some(node_ref) = doc.graph.root_by_name("Server") {
        doc.graph.remove_node(node_ref);
    }
    let mut get_handlers = BTreeMap::new();
    let mut put_handlers = BTreeMap::new();
    let mut post_handlers = BTreeMap::new();
    let mut delete_handlers = BTreeMap::new();
    let mut head_handlers = BTreeMap::new();
    let mut patch_handlers = BTreeMap::new();
    for (id, dref) in &doc.graph.data.store {
        if id.starts_with(FUNC_KIND) {
            if let Ok(func) = dref.get_value::<SFunc>() {
                if let Some(path) = func.attributes.get("GET") {
                    get_handlers.insert(path.to_string(), dref.data_ref());
                } else if let Some(path) = func.attributes.get("PUT") {
                    put_handlers.insert(path.to_string(), dref.data_ref());
                } else if let Some(path) = func.attributes.get("PATCH") {
                    patch_handlers.insert(path.to_string(), dref.data_ref());
                } else if let Some(path) = func.attributes.get("DELETE") {
                    delete_handlers.insert(path.to_string(), dref.data_ref());
                } else if let Some(path) = func.attributes.get("POST") {
                    post_handlers.insert(path.to_string(), dref.data_ref());
                } else if let Some(path) = func.attributes.get("HEAD") {
                    head_handlers.insert(path.to_string(), dref.data_ref());
                }
            }
        }
    }
    let state = ServerState {
        doc: Arc::new(Mutex::new(doc)),
        opaque_errors: opaque_server_errors,
        get_handlers: Arc::new(get_handlers),
        put_handlers: Arc::new(put_handlers),
        post_handlers: Arc::new(post_handlers),
        delete_handlers: Arc::new(delete_handlers),
        head_handlers: Arc::new(head_handlers),
        patch_handlers: Arc::new(patch_handlers),
    };

    // Create the application router
    let app = Router::new()
        .route("/{*path}", get(get_request_handler)
            .head(head_request_handler)
            .post(post_request_handler)
            .put(put_request_handler)
            .patch(patch_request_handler)
            .delete(delete_request_handler))
        .layer(GovernorLayer {
            config: governor_conf
        })
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

/// Response object, implementing IntoResonse.
pub struct StofResponse {
    pub headers: HeaderMap,
    pub status: StatusCode,
    pub str_body: String,
    pub bytes_body: Option<Bytes>, // if present, will get sent in place of the str_body
}
impl IntoResponse for StofResponse {
    fn into_response(self) -> axum::response::Response {
        let mut builder = Response::builder().status(self.status);
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        let response;
        if let Some(bytes) = self.bytes_body {
            if !self.headers.contains_key(CONTENT_TYPE) {
                builder = builder.header(CONTENT_TYPE, "application/octet-stream");
            }
            response = builder.body(Body::from(bytes));
        } else {
            if !self.headers.contains_key(CONTENT_TYPE) {
                builder = builder.header(CONTENT_TYPE, "text/plain");
            }
            response = builder.body(Body::from(self.str_body));
        }
        response.unwrap()
    }
}
impl StofResponse {
    /// Creates a response from this value with a success status code.
    pub fn val_response(doc: &SDoc, value: SVal) -> Self {
        let mut status = StatusCode::OK;
        let mut headers = HeaderMap::new();
        let mut str_body = String::default();
        let mut bytes_body = None;
        let match_val = value.unbox();
        match match_val {
            SVal::Blob(blob) => {
                headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
                bytes_body = Some(Bytes::from(blob));
            },
            SVal::String(value) => {
                headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
                str_body = value;
            },
            SVal::Map(map) => {
                if let Some(format_val) = map.get(&SVal::String("format".into())) {
                    if let Some(format) = doc.formats.get(&format_val.to_string()) {
                        headers.insert("format", format.format().parse().unwrap());
                        headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                    }
                }
                if let Some(headers_val) = map.get(&SVal::String("headers".into())) {
                    match headers_val {
                        SVal::Map(headers_map) => {
                            for (k, v) in headers_map {
                                let key = k.to_string();
                                headers.insert(HeaderName::from_str(&key).unwrap(), v.to_string().parse().unwrap());
                            }
                        },
                        SVal::Array(values) => {
                            for tup in values {
                                match tup {
                                    SVal::Tuple(tup) => {
                                        if tup.len() == 2 {
                                            let key = tup[0].to_string();
                                            headers.insert(HeaderName::from_str(&key).unwrap(), tup[1].to_string().parse().unwrap());
                                        }
                                    },
                                    _ => {}
                                }
                            }
                        },
                        _ => {}
                    }
                }
                if let Some(body_val) = map.get(&SVal::String("body".into())) {
                    // Get content type to use from the headers if any
                    let content_type = headers.get(CONTENT_TYPE);

                    match body_val {
                        SVal::String(value) => {
                            if content_type.is_none() { // give opportunity to override with the map above
                                headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
                            }
                            str_body = value.clone();
                        },
                        SVal::Blob(blob) => {
                            if content_type.is_none() { // give opportunity to override with the map above
                                headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
                            }
                            bytes_body = Some(Bytes::from(blob.clone()));
                        },
                        SVal::Object(nref) => {
                            let format;
                            if let Some(value) = headers.get("format") {
                                format = value.to_str().unwrap().to_owned();
                            } else if let Some(ctype) = content_type {
                                format = ctype.to_str().unwrap().to_owned();
                            } else {
                                format = "json".to_owned();
                            }
                            if format != "bstof" {
                                if let Ok(result) = doc.export_string("main", &format, Some(nref)) {
                                    str_body = result;
                                    if let Some(format) = doc.formats.get(&format) {
                                        headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                                    }
                                } else if let Ok(result) = doc.export_bytes("main", &format, Some(nref)) {
                                    bytes_body = Some(result);
                                    if let Some(format) = doc.formats.get(&format) {
                                        headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                                    }
                                } else if let Ok(result) = doc.export_bytes("main", "bytes", Some(nref)) {
                                    bytes_body = Some(result);
                                    if let Some(format) = doc.formats.get("bytes") {
                                        headers.insert(CONTENT_TYPE, format.content_type().parse().unwrap());
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }
                if let Some(status_val) = map.get(&SVal::String("status".into())) {
                    let status_res = StatusCode::from_str(&status_val.to_string());
                    match status_res {
                        Ok(code) => status = code,
                        Err(_inv) => status = StatusCode::MULTI_STATUS,
                    }
                }
            },
            _ => {}
        }
        Self {
            status,
            headers,
            str_body,
            bytes_body,
        }
    }

    /// Error response.
    pub fn error(code: StatusCode, message: &str) -> Self {
        Self {
            headers: HeaderMap::new(),
            status: code,
            str_body: message.to_owned(),
            bytes_body: None,
        }
    }
}

/// Request handler.
async fn request_handler(state: ServerState, path: String, query: BTreeMap<String, String>, headers: HeaderMap, mut body: Bytes, method: Method) -> impl IntoResponse {
    let dref = state.handler(method, &path);
    let mut doc;
    let function;
    match dref {
        Ok(dref) => {
            let tmp = state.doc.lock().await;
            if let Ok(func) = SData::data::<SFunc>(&tmp.graph, dref) {
                function = func;
                doc = tmp.clone();
            } else {
                return StofResponse::error(StatusCode::NOT_FOUND, &format!("request handler not found at the path: {}", path));
            }
        },
        Err(error) => {
            return StofResponse::error(StatusCode::NOT_FOUND, &format!("request handler not found at the path: {}: {}", path, error.to_string()));
        }
    }

    let parse_body_res;
    if let Some(content_type) = headers.get(CONTENT_TYPE) {
        let ctype = content_type.to_str().unwrap();
        parse_body_res = doc.header_import("main", ctype, ctype, &mut body, "Request");
    } else {
        parse_body_res = doc.header_import("main", "bytes", "bytes", &mut body, "Request");
    }
    match parse_body_res {
        Ok(_) => {},
        Err(_) => return StofResponse::error(StatusCode::BAD_REQUEST, "failed to parse request body into the document")
    }
    let req;
    if let Some(obj) = doc.graph.root_by_name("Request") {
        req = obj;
    } else {
        return StofResponse::error(StatusCode::BAD_REQUEST, "failed to parse request body into the document");
    }

    let query: BTreeMap<SVal, SVal> = query.into_iter().map(|(key, value)| (SVal::String(key), SVal::String(value))).collect();
    let mut header_map: BTreeMap<SVal, SVal> = BTreeMap::new();
    for (key, value) in &headers {
        header_map.insert(SVal::String(key.as_str().to_owned()), SVal::String(value.to_str().unwrap().to_owned()));
    }

    // fn get(requst: obj, headers: map, query: map) { .... }
    let mut parameters = Vec::new();
    let mut added_headers = false;
    for param in &function.params {
        if param.ptype.is_object() {
            // put the request object into the parameters
            parameters.push(SVal::Object(req.clone()));
        } else if param.ptype.is_map() {
            // headers first, then query unless name is literally query or headers...
            if param.name != "query" && (param.name == "headers" || !added_headers) {
                added_headers = true;
                parameters.push(SVal::Map(header_map.clone()));
            } else if param.name != "headers" && (param.name == "query" || added_headers) {
                parameters.push(SVal::Map(query.clone()));
            }
        }
    }
    let response = doc.call(&function, parameters);
    match response {
        Ok(response) => {
            StofResponse::val_response(&doc, response)
        },
        Err(error) => {
            if state.opaque_errors {
                StofResponse::error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            } else {
                StofResponse::error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string(&doc.graph))
            }
        }
    }
}

/// Post request handler.
async fn post_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    request_handler(state, path, query, headers, body, Method::POST).await
}

/// Put request handler.
async fn put_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    request_handler(state, path, query, headers, body, Method::PUT).await
}

/// Patch request handler.
async fn patch_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    request_handler(state, path, query, headers, body, Method::PATCH).await
}

/// Delete request handler.
async fn delete_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    request_handler(state, path, query, headers, body, Method::DELETE).await
}

/// Get request handler.
async fn get_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    request_handler(state, path, query, headers, body, Method::GET).await
}

/// Head request handler.
async fn head_request_handler(State(state): State<ServerState>, Path(path): Path<String>, Query(query): Query<BTreeMap<String, String>>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    request_handler(state, path, query, headers, body, Method::HEAD).await
}


#[cfg(test)]
mod tests {
    use stof::SDoc;
    use super::serve;


    #[test]
    fn test_serve() {
        let doc = SDoc::file("src/server/test/server.stof", "stof").unwrap();
        serve(doc);
    }
}
