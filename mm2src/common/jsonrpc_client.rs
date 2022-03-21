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
pub struct JsonRpcBatchIds(Vec<String>);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JsonRpcRequestEnum {
    Single(JsonRpcRequest),
    Batch(JsonRpcBatchRequests),
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
}

/// Serializable RPC request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JsonRpcBatchRequests(Vec<JsonRpcRequest>);

impl JsonRpcBatchRequests {
    pub fn ids(&self) -> JsonRpcBatchIds { JsonRpcBatchIds(self.0.iter().map(|req| req.id.clone()).collect()) }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcResponseEnum {
    Single(JsonRpcResponse),
    Batch(JsonRpcBatchResponses),
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

#[derive(Clone, Debug, Deserialize)]
pub struct JsonRpcBatchResponses(Vec<JsonRpcResponse>);

impl JsonRpcBatchResponses {
    pub fn ids(&self) -> JsonRpcBatchIds { JsonRpcBatchIds(self.0.iter().map(|res| res.id.clone()).collect()) }
}

#[derive(Clone, Debug)]
pub struct JsonRpcError {
    /// Additional member contains an instance info that implements the JsonRpcClient trait.
    /// The info is used in particular to supplement the error info.
    pub client_info: String,
    /// Source Rpc request.
    pub request: JsonRpcRequest,
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
    Box<dyn Future<Item = (JsonRpcRemoteAddr, JsonRpcResponse), Error = String> + Send + 'static>;
pub type RpcRes<T> = Box<dyn Future<Item = T, Error = JsonRpcError> + Send + 'static>;

pub trait JsonRpcClient {
    fn version(&self) -> &'static str;

    fn next_id(&self) -> String;

    /// Get info that is used in particular to supplement the error info
    fn client_info(&self) -> String;

    fn transport(&self, request: JsonRpcRequest) -> JsonRpcResponseFut;

    fn send_request<T: DeserializeOwned + Send + 'static>(&self, request: JsonRpcRequest) -> RpcRes<T> {
        let client_info = self.client_info();
        Box::new(
            self.transport(request.clone())
                .then(move |result| process_transport_result(result, client_info, request)),
        )
    }
}

/// The trait is used when the rpc client instance has more than one remote endpoints.
pub trait JsonRpcMultiClient: JsonRpcClient {
    fn transport_exact(&self, to_addr: String, request: JsonRpcRequest) -> JsonRpcResponseFut;

    fn send_request_to<T: DeserializeOwned + Send + 'static>(
        &self,
        to_addr: &str,
        request: JsonRpcRequest,
    ) -> RpcRes<T> {
        let client_info = self.client_info();
        Box::new(
            self.transport_exact(to_addr.to_owned(), request.clone())
                .then(move |result| process_transport_result(result, client_info, request)),
        )
    }
}

fn process_transport_result<T: DeserializeOwned + Send + 'static>(
    result: Result<(JsonRpcRemoteAddr, JsonRpcResponse), String>,
    client_info: String,
    request: JsonRpcRequest,
) -> Result<T, JsonRpcError> {
    let (remote_addr, response) = match result {
        Ok(r) => r,
        Err(e) => {
            return Err(JsonRpcError {
                client_info,
                request,
                error: JsonRpcErrorType::Transport(e),
            })
        },
    };

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
