use spiderweb_protocol::generated::*;
use spiderweb_protocol::protocol::stringify_control_request;

fn main() {
    let request = ControlRequestEnvelope::Version(ControlEnvelope {
        channel: Channel::Control,
        message_type: ControlMessageType::Version,
        id: Some("control-version".into()),
        ok: None,
        payload: Some(ControlVersionRequestPayload {
            protocol: CONTROL_PROTOCOL.into(),
        }),
    });
    println!("{}", stringify_control_request(&request).unwrap());
}
