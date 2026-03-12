use spiderweb_protocol::generated::*;
use spiderweb_protocol::protocol::stringify_control_request;

fn main() {
    let request = ControlRequestEnvelope::Connect(ControlEnvelope {
        channel: Channel::Control,
        message_type: ControlMessageType::Connect,
        id: Some("control-connect".into()),
        ok: None,
        payload: Some(EmptyObject::default()),
    });
    println!("{}", stringify_control_request(&request).unwrap());
}
