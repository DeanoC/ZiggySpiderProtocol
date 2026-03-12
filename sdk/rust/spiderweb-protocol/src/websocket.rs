use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::protocol::{SpiderProtocolError, TextTransport};

pub struct TokioWebSocketTextTransport {
    stream: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
}

impl TokioWebSocketTextTransport {
    pub async fn connect(url: &str) -> Result<Self, SpiderProtocolError> {
        let (stream, _) = connect_async(url)
            .await
            .map_err(|error| SpiderProtocolError::new("websocket_open_failed", "websocket connection failed before open").with_details(serde_json::Value::String(error.to_string())))?;
        Ok(Self { stream })
    }
}

#[async_trait]
impl TextTransport for TokioWebSocketTextTransport {
    async fn send_text(&mut self, text: String) -> Result<(), SpiderProtocolError> {
        self.stream
            .send(Message::Text(text))
            .await
            .map_err(|error| SpiderProtocolError::new("websocket_write_failed", "websocket text send failed").with_details(serde_json::Value::String(error.to_string())))
    }

    async fn receive_text(&mut self) -> Result<String, SpiderProtocolError> {
        while let Some(message) = self.stream.next().await {
            let message = message
                .map_err(|error| SpiderProtocolError::new("websocket_read_failed", "websocket read failed").with_details(serde_json::Value::String(error.to_string())))?;
            match message {
                Message::Text(text) => return Ok(text),
                Message::Binary(_) => {
                    return Err(SpiderProtocolError::new("invalid_frame_type", "websocket transport expected a text frame"));
                }
                Message::Close(_) => {
                    return Err(SpiderProtocolError::new("websocket_closed", "websocket closed"));
                }
                Message::Ping(_) | Message::Pong(_) => {}
                _ => {}
            }
        }
        Err(SpiderProtocolError::new("websocket_closed", "websocket closed"))
    }

    async fn close(&mut self) -> Result<(), SpiderProtocolError> {
        self.stream
            .close(None)
            .await
            .map_err(|error| SpiderProtocolError::new("websocket_close_failed", "websocket close failed").with_details(serde_json::Value::String(error.to_string())))
    }
}
