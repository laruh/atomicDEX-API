use futures01::Future;
use serde::de::DeserializeOwned;
use serde_json::{self as json, Value as Json};
use std::fmt;

/// Macro generating functions for RPC requests.
/// Args must implement/derive Serialize trait.
/// Generates params vector from input args, builds the request and sends it.
#[macro_export]
macro_rules! rpc_func {
    ($selff:ident, $method:expr $(, $arg_name:expr)*) => {{
        let mut params = vec![];
        $(
            params.push(json::value::to_value($arg_name).unwrap());
        )*
        let request = JsonRpcRequest {
            jsonrpc: $selff.version().into(),
            id: $selff.next_id(),
            method: $method.into(),
            params
        };
        $selff.send_request(request)
    }}
}

/// Macro generating functions for RPC requests.
/// Send the RPC request to specified remote endpoint using the passed address.
/// Args must implement/derive Serialize trait.
/// Generates params vector from input args, builds the request and sends it.
#[macro_export]
macro_rules! rpc_func_from {
    ($selff:ident, $address:expr, $method:expr $(, $arg_name:ident)*) => {{
        let mut params = vec![];
        $(
            params.push(json::value::to_value($arg_name).unwrap());
        )*
        let request = JsonRpcRequest {
            jsonrpc: $selff.version().into(),
            id: $selff.next_id(),
            method: $method.into(),
            params
        };
        $selff.send_request_to($address, request)
    }}
}

/// Address of server from which an Rpc response was received
#[derive(Clone, Default)]
pub struct JsonRpcRemoteAddr(pub String);

impl fmt::Debug for JsonRpcRemoteAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<JsonRpcRemoteAddr> for String {
    fn from(addr: JsonRpcRemoteAddr) -> Self { addr.0 }
}

impl From<String> for JsonRpcRemoteAddr {
    fn from(addr: String) -> Self { JsonRpcRemoteAddr(addr) }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum JsonRpcId {
    Single(String),
    Batch(Vec<String>),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JsonRpcRequestEnum {
    Single(JsonRpcRequest),
    Batch(JsonRpcBatchRequest),
}

impl JsonRpcRequestEnum {
    pub fn rpc_id(&self) -> JsonRpcId {
        match self {
            JsonRpcRequestEnum::Single(single) => single.rpc_id(),
            JsonRpcRequestEnum::Batch(batch) => batch.rpc_id(),
        }
    }
}

impl fmt::Debug for JsonRpcRequestEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonRpcRequestEnum::Single(single) => single.fmt(f),
            JsonRpcRequestEnum::Batch(batch) => batch.fmt(f),
        }
    }
}

/// Serializable RPC request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: String,
    pub method: String,
    pub params: Vec<Json>,
}

impl JsonRpcRequest {
    pub fn get_id(&self) -> &str { &self.id }

    pub fn rpc_id(&self) -> JsonRpcId { JsonRpcId::Single(self.id.clone()) }
}

impl From<JsonRpcRequest> for JsonRpcRequestEnum {
    fn from(single: JsonRpcRequest) -> Self { JsonRpcRequestEnum::Single(single) }
}

/// Serializable RPC request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JsonRpcBatchRequest(Vec<JsonRpcRequest>);

impl JsonRpcBatchRequest {
    pub fn rpc_id(&self) -> JsonRpcId { JsonRpcId::Batch(self.0.iter().map(|req| req.id.clone()).collect()) }

    pub fn len(&self) -> usize { self.0.len() }

    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl From<JsonRpcBatchRequest> for JsonRpcRequestEnum {
    fn from(batch: JsonRpcBatchRequest) -> Self { JsonRpcRequestEnum::Batch(batch) }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResponseEnum {
    Single(JsonRpcResponse),
    Batch(JsonRpcBatchResponse),
}

impl JsonRpcResponseEnum {
    pub fn rpc_id(&self) -> JsonRpcId {
        match self {
            JsonRpcResponseEnum::Single(single) => single.rpc_id(),
            JsonRpcResponseEnum::Batch(batch) => batch.rpc_id(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct JsonRpcResponse {
    #[serde(default)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub result: Json,
    #[serde(default)]
    pub error: Json,
}

impl JsonRpcResponse {
    pub fn rpc_id(&self) -> JsonRpcId { JsonRpcId::Single(self.id.clone()) }
}

#[derive(Clone, Debug, Deserialize)]
pub struct JsonRpcBatchResponse(Vec<JsonRpcResponse>);

impl JsonRpcBatchResponse {
    pub fn rpc_id(&self) -> JsonRpcId { JsonRpcId::Batch(self.0.iter().map(|res| res.id.clone()).collect()) }

    pub fn len(&self) -> usize { self.0.len() }

    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl IntoIterator for JsonRpcBatchResponse {
    type Item = JsonRpcResponse;
    type IntoIter = std::vec::IntoIter<JsonRpcResponse>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

#[derive(Clone, Debug)]
pub struct JsonRpcError {
    /// Additional member contains an instance info that implements the JsonRpcClient trait.
    /// The info is used in particular to supplement the error info.
    pub client_info: String,
    /// Source Rpc request.
    pub request: JsonRpcRequestEnum,
    /// Error type.
    pub error: JsonRpcErrorType,
}

#[derive(Clone, Debug)]
pub enum JsonRpcErrorType {
    /// Error from transport layer
    Transport(String),
    /// Response parse error
    Parse(JsonRpcRemoteAddr, String),
    /// The JSON-RPC error returned from server
    Response(JsonRpcRemoteAddr, Json),
}

impl JsonRpcErrorType {
    pub fn is_transport(&self) -> bool { matches!(*self, JsonRpcErrorType::Transport(_)) }
}

impl fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{:?}", self) }
}

pub type JsonRpcResponseFut =
    Box<dyn Future<Item = (JsonRpcRemoteAddr, JsonRpcResponseEnum), Error = String> + Send + 'static>;
pub type RpcRes<T> = Box<dyn Future<Item = T, Error = JsonRpcError> + Send + 'static>;

pub trait JsonRpcClient {
    fn version(&self) -> &'static str;

    fn next_id(&self) -> String;

    /// Get info that is used in particular to supplement the error info
    fn client_info(&self) -> String;

    fn transport(&self, request: JsonRpcRequestEnum) -> JsonRpcResponseFut;

    fn send_request<T: DeserializeOwned + Send + 'static>(&self, request: JsonRpcRequest) -> RpcRes<T> {
        let client_info = self.client_info();
        Box::new(
            self.transport(JsonRpcRequestEnum::Single(request.clone()))
                .then(move |result| process_transport_single_result(result, client_info, request)),
        )
    }

    fn send_batch_request<T: DeserializeOwned + Send + 'static>(&self, request: JsonRpcBatchRequest) -> RpcRes<Vec<T>> {
        let client_info = self.client_info();
        Box::new(
            self.transport(JsonRpcRequestEnum::Batch(request.clone()))
                .then(move |result| process_transport_batch_result(result, client_info, request)),
        )
    }
}

/// The trait is used when the rpc client instance has more than one remote endpoints.
pub trait JsonRpcMultiClient: JsonRpcClient {
    fn transport_exact(&self, to_addr: String, request: JsonRpcRequestEnum) -> JsonRpcResponseFut;

    fn send_request_to<T: DeserializeOwned + Send + 'static>(
        &self,
        to_addr: &str,
        request: JsonRpcRequest,
    ) -> RpcRes<T> {
        let client_info = self.client_info();
        Box::new(
            self.transport_exact(to_addr.to_owned(), JsonRpcRequestEnum::Single(request.clone()))
                .then(move |result| process_transport_single_result(result, client_info, request)),
        )
    }
}

fn process_transport_single_result<T: DeserializeOwned + Send + 'static>(
    result: Result<(JsonRpcRemoteAddr, JsonRpcResponseEnum), String>,
    client_info: String,
    request: JsonRpcRequest,
) -> Result<T, JsonRpcError> {
    let request = JsonRpcRequestEnum::Single(request);

    match result {
        Ok((remote_addr, JsonRpcResponseEnum::Single(single))) => {
            process_single_response(client_info, remote_addr, request, single)
        },
        Ok((remote_addr, JsonRpcResponseEnum::Batch(batch))) => {
            let error = ERRL!("Expeced single response, found batch response: {:?}", batch);
            Err(JsonRpcError {
                client_info,
                request,
                error: JsonRpcErrorType::Parse(remote_addr, error),
            })
        },
        Err(e) => Err(JsonRpcError {
            client_info,
            request,
            error: JsonRpcErrorType::Transport(e),
        }),
    }
}

fn process_transport_batch_result<T: DeserializeOwned + Send + 'static>(
    result: Result<(JsonRpcRemoteAddr, JsonRpcResponseEnum), String>,
    client_info: String,
    request: JsonRpcBatchRequest,
) -> Result<Vec<T>, JsonRpcError> {
    let expected_len = request.len();
    let request = JsonRpcRequestEnum::Batch(request);

    let (remote_addr, response) = match result {
        Ok((remote_addr, JsonRpcResponseEnum::Batch(batch))) => (remote_addr, batch),
        Ok((remote_addr, JsonRpcResponseEnum::Single(single))) => {
            let error = ERRL!("Expected batch response, found single response: {:?}", single);
            return Err(JsonRpcError {
                client_info,
                request,
                error: JsonRpcErrorType::Parse(remote_addr, error),
            });
        },
        Err(e) => {
            return Err(JsonRpcError {
                client_info,
                request,
                error: JsonRpcErrorType::Transport(e),
            })
        },
    };

    if response.len() != expected_len {
        let error = ERRL!(
            "Expected '{}' elements in batch response, found '{}'",
            expected_len,
            response.len()
        );
        return Err(JsonRpcError {
            client_info,
            request,
            error: JsonRpcErrorType::Parse(remote_addr, error),
        });
    }

    response
        .into_iter()
        .map(|resp| process_single_response(client_info.clone(), remote_addr.clone(), request.clone(), resp))
        .collect()
}

fn process_single_response<T: DeserializeOwned + Send + 'static>(
    client_info: String,
    remote_addr: JsonRpcRemoteAddr,
    request: JsonRpcRequestEnum,
    response: JsonRpcResponse,
) -> Result<T, JsonRpcError> {
    if !response.error.is_null() {
        return Err(JsonRpcError {
            client_info,
            request,
            error: JsonRpcErrorType::Response(remote_addr, response.error),
        });
    }

    json::from_value(response.result.clone()).map_err(|e| JsonRpcError {
        client_info,
        request,
        error: JsonRpcErrorType::Parse(
            remote_addr,
            ERRL!("error {:?} parsing result from response {:?}", e, response),
        ),
    })
}
