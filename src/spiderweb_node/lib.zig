pub const fs_node_main = @import("fs_node_main.zig");
pub const fs_node_server = @import("fs_node_server.zig");
pub const fs_node_service = @import("fs_node_service.zig");
pub const fs_node_ops = @import("fs_node_ops.zig");
pub const node_capability_providers = @import("node_capability_providers.zig");
pub const service_manifest = @import("service_manifest.zig");
pub const namespace_driver = @import("namespace_driver.zig");
pub const service_runtime_manager = @import("service_runtime_manager.zig");
pub const plugin_loader_native = @import("plugin_loader_native.zig");
pub const plugin_loader_process = @import("plugin_loader_process.zig");
pub const plugin_loader_wasm = @import("plugin_loader_wasm.zig");

pub const fs_source_adapter = @import("fs_source_adapter.zig");
pub const fs_source_adapter_factory = @import("fs_source_adapter_factory.zig");
pub const fs_linux_source_adapter = @import("fs_linux_source_adapter.zig");
pub const fs_posix_source_adapter = @import("fs_posix_source_adapter.zig");
pub const fs_windows_source_adapter = @import("fs_windows_source_adapter.zig");
pub const fs_local_source_adapter = @import("fs_local_source_adapter.zig");
pub const fs_gdrive_source_adapter = @import("fs_gdrive_source_adapter.zig");
pub const fs_namespace_source_adapter = @import("fs_namespace_source_adapter.zig");

pub const fs_gdrive_backend = @import("fs_gdrive_backend.zig");
pub const credential_store = @import("credential_store.zig");
pub const fs_watch_runtime = @import("fs_watch_runtime.zig");

test {
    _ = fs_node_main;
    _ = fs_node_server;
    _ = fs_node_service;
    _ = fs_node_ops;
    _ = node_capability_providers;
    _ = service_manifest;
    _ = namespace_driver;
    _ = service_runtime_manager;
    _ = plugin_loader_native;
    _ = plugin_loader_process;
    _ = plugin_loader_wasm;
    _ = fs_source_adapter;
    _ = fs_source_adapter_factory;
    _ = fs_linux_source_adapter;
    _ = fs_posix_source_adapter;
    _ = fs_windows_source_adapter;
    _ = fs_local_source_adapter;
    _ = fs_gdrive_source_adapter;
    _ = fs_namespace_source_adapter;
    _ = fs_gdrive_backend;
    _ = credential_store;
    _ = fs_watch_runtime;
}
