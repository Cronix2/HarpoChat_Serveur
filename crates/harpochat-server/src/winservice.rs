// SPDX-License-Identifier: Apache-2.0
//! Windows service (spec §12.3): `harpochat-server service install` registers
//! the node with the Service Control Manager, which then starts
//! `harpochat-server --dir <dir> run --service`. In that mode the node
//! reports its state to the SCM and stops cleanly (RAM wiped) on Stop or
//! system shutdown.
//!
//! The service runs as `NT AUTHORITY\LocalService` (no administrator rights);
//! the data directory must be readable by that account (see
//! `docs/operators/services.md`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::node::Node;

/// Name registered with the SCM.
pub const SERVICE_NAME: &str = "HarpoChat";
const DISPLAY_NAME: &str = "HarpoChat mesh node";
const ACCOUNT: &str = r"NT AUTHORITY\LocalService";

/// The node to run, handed from `main` to the service entry point.
static NODE: Mutex<Option<Node>> = Mutex::new(None);
/// Exit code of the node, read back once the dispatcher returns.
static EXIT: Mutex<i32> = Mutex::new(0);

/// Register the service (needs an administrator prompt).
pub fn install(dir: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("gestionnaire de services : {e} (invite administrateur requise)"))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("--dir"),
            dir.into_os_string(),
            OsString::from("run"),
            OsString::from("--service"),
        ],
        dependencies: vec![],
        account_name: Some(OsString::from(ACCOUNT)),
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| format!("création du service : {e}"))?;
    let _ = service
        .set_description("Nœud du mesh HarpoChat : ne voit jamais le contenu ni qui parle à qui.");
    Ok(())
}

/// Stop and remove the service.
pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("gestionnaire de services : {e}"))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| format!("service introuvable : {e}"))?;
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
        }
    }
    service
        .delete()
        .map_err(|e| format!("suppression du service : {e}"))
}

define_windows_service!(ffi_service_main, service_main);

fn status(state: ServiceState, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let Some(node) = NODE.lock().expect("node").take() else {
        return;
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = Mutex::new(Some(stop_tx));
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = stop_tx.lock().expect("stop").take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let _ = handle.set_service_status(status(ServiceState::Running, 0));
    let code = crate::cli::serve_until(node, async {
        let _ = stop_rx.await;
    });
    *EXIT.lock().expect("exit") = code;
    let _ = handle.set_service_status(status(ServiceState::Stopped, code as u32));
}

/// Run `node` under the SCM (blocks until the service stops).
pub fn run(node: Node) -> i32 {
    *NODE.lock().expect("node") = Some(node);
    if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!(
            "erreur : `run --service` est lancé par le gestionnaire de services Windows, \
             pas à la main ({e})"
        );
        return crate::cli::EXIT_USAGE;
    }
    *EXIT.lock().expect("exit")
}

/// Where the service looks for its data (for messages).
pub fn describe(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
}
