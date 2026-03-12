use spiderweb_protocol::generated::*;
use spiderweb_protocol::protocol::stringify_control_request;

fn main() {
    let request = ControlRequestEnvelope::WorkspaceBindSet(ControlEnvelope {
        channel: Channel::Control,
        message_type: ControlMessageType::WorkspaceBindSet,
        id: Some("bind-1".into()),
        ok: None,
        payload: Some(WorkspaceBindSetRequest {
            workspace_id: "ws-1".into(),
            workspace_token: None,
            bind_path: "/app".into(),
            target_path: "/projects/demo/app".into(),
        }),
    });
    println!("{}", stringify_control_request(&request).unwrap());
}
