use spiderweb_protocol::generated::*;
use spiderweb_protocol::protocol::stringify_acheron_request;

fn main() {
    let request = AcheronRequestEnvelope::FsTHello(AcheronPayloadEnvelope {
        channel: Channel::Acheron,
        message_type: AcheronMessageType::FsTHello,
        tag: Some(1),
        ok: None,
        payload: Some(FsHelloRequest {
            protocol: NODE_FS_PROTOCOL.into(),
            proto: NODE_FS_PROTO,
            auth_token: None,
            node_id: None,
            node_secret: None,
        }),
    });
    println!("{}", stringify_acheron_request(&request).unwrap());
}
