// SPDX-License-Identifier: Apache-2.0
//! Command line (spec §12.2). Exit codes: 0 ok, 1 runtime error, 2 usage or
//! configuration error.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use harpochat_core::bootstrap::RootEntry;
use harpochat_core::directory::{Revoke, VERSION as DIR_VERSION};
use harpochat_core::invite::encode_token;
use harpochat_core::signed::Signed;
use harpochat_core::{cbor, descriptor};

use crate::config::{Config, CONFIG_FILE};
use crate::keystore::{self, NodeKeys, KEY_FILE};
use crate::node::{Node, NodeError};

/// Exit code: success.
pub const EXIT_OK: i32 = 0;
/// Exit code: runtime failure.
pub const EXIT_RUNTIME: i32 = 1;
/// Exit code: usage or configuration error.
pub const EXIT_USAGE: i32 = 2;

/// `harpochat-server` — nœud du mesh HarpoChat.
#[derive(Debug, Parser)]
#[command(name = "harpochat-server", version, about)]
pub struct Cli {
    /// Répertoire de données (défaut : $HARPOCHAT_HOME, sinon ./harpochat-data).
    #[arg(long, global = true)]
    pub dir: Option<PathBuf>,
    /// Commande.
    #[command(subcommand)]
    pub cmd: Command,
}

/// Sub-commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Génère les clés et la configuration d'un nouveau nœud.
    Init {
        /// Crée un nœud racine (premier nœud du mesh).
        #[arg(long)]
        root: bool,
        /// Adresse publique `wss://…` du nœud (répétable).
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
    },
    /// Démarre le nœud.
    Run {
        /// Vérifie la configuration et les clés, puis quitte.
        #[arg(long)]
        check: bool,
        /// Lancé par le gestionnaire de services Windows (`service install`).
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Installe ou retire le service Windows (sous Linux : unité systemd fournie).
    Service {
        /// Action.
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Crée un jeton de parrainage à usage unique pour un nouveau nœud.
    InviteNode {
        /// Durée de validité en heures (48 au plus).
        #[arg(long, default_value_t = 48)]
        hours: u64,
    },
    /// Rejoint le mesh avec un jeton `hcn1-…` (`-` : lu sur l'entrée standard).
    Join {
        /// Le jeton donné par le parrain.
        token: String,
        /// Adresse publique `wss://…` du nouveau nœud (répétable).
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
    },
    /// Interroge le nœud en marche comme le ferait l'app : annuaire signé, vérifié.
    Status,
    /// Révoque un nœud que ce nœud a parrainé (ou n'importe lequel, depuis une racine).
    Revoke {
        /// Identité du nœud (64 caractères hexadécimaux).
        node_id: String,
    },
}

/// `service` actions.
#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    /// Enregistre le service « HarpoChat » (démarrage automatique, compte LocalService).
    Install,
    /// Arrête et supprime le service.
    Uninstall,
}

/// Data directory: `--dir`, else `$HARPOCHAT_HOME`, else `./harpochat-data`.
pub fn data_dir(cli: &Cli) -> PathBuf {
    cli.dir
        .clone()
        .or_else(|| std::env::var_os("HARPOCHAT_HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("harpochat-data"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fail(code: i32, msg: impl std::fmt::Display) -> i32 {
    eprintln!("erreur : {msg}");
    code
}

/// Execute the parsed command line; returns the process exit code.
pub fn run_cli(cli: Cli) -> i32 {
    let dir = data_dir(&cli);
    match cli.cmd {
        Command::Init { root, endpoints } => init(&dir, root, endpoints),
        Command::Run { check, service } => run(&dir, check, service),
        Command::Service { action } => service(&dir, action),
        Command::InviteNode { hours } => invite_node(&dir, hours),
        Command::Join { token, endpoints } => join(&dir, &token, endpoints),
        Command::Revoke { node_id } => revoke(&dir, &node_id),
        Command::Status => status(&dir),
    }
}

fn invite_node(dir: &Path, hours: u64) -> i32 {
    let node = match load(dir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    match crate::sponsor::create_invite(&node, now(), hours.saturating_mul(3600)) {
        Ok(invite) => {
            // The token is a secret: printed once, never logged.
            println!("{}", encode_token(&invite));
            eprintln!(
                "  ↳ valable {hours} h, utilisable une seule fois. C'est un secret :                  transmettez-le par un canal de confiance."
            );
            EXIT_OK
        }
        Err(e) => fail(EXIT_USAGE, e),
    }
}

fn join(dir: &Path, token: &str, endpoints: Vec<String>) -> i32 {
    let token = if token == "-" {
        let mut t = String::new();
        if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut t) {
            return fail(EXIT_USAGE, format!("lecture du jeton impossible : {e}"));
        }
        t
    } else {
        token.to_string()
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(EXIT_RUNTIME, format!("runtime : {e}")),
    };
    match rt.block_on(crate::join::join_mesh(dir, &token, endpoints, now())) {
        Ok(j) => {
            println!("✔ clés générées · id: {}", hex::encode(j.id));
            println!("✔ parrain joint · {}", hex::encode(j.sponsor));
            println!(
                "✔ certificat de parrainage reçu (chaîne de {} maillon(s), {} racine(s))",
                j.chain_len, j.roots
            );
            println!(
                "→ lancez `harpochat-server --dir {} run` : le nœud s'annoncera au mesh",
                dir.display()
            );
            EXIT_OK
        }
        Err(e) => {
            let code = match e {
                crate::join::JoinError::Token(_)
                | crate::join::JoinError::Exists
                | crate::join::JoinError::Config(_) => EXIT_USAGE,
                _ => EXIT_RUNTIME,
            };
            fail(code, e)
        }
    }
}

fn status(dir: &Path) -> i32 {
    use harpochat_core::directory::{verify_directory, Directory};
    use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
    let node = match load(dir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    let id = node.keys.identity.public();
    let roots = node.trusted_roots().unwrap_or_default();
    let addr = node.config.listen.addr.replace("0.0.0.0", "127.0.0.1");
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(EXIT_RUNTIME, format!("runtime : {e}")),
    };
    let answer = rt.block_on(async {
        let sock = tokio::net::lookup_host(&addr).await.ok()?.next()?;
        // An anonymous link, exactly like a phone's.
        let (mut r, mut w, _) = crate::net::connect(
            sock,
            &harpochat_core::keys::X25519Secret::generate(),
            None,
            Some(id),
        )
        .await
        .ok()?;
        w.send(
            &LinkFrame {
                kind: FrameKind::DirectoryReq,
                body: Vec::new(),
            },
            SizeClass::Small,
        )
        .await
        .ok()?;
        let wait = async {
            loop {
                let (_, f) = r.recv().await.ok()?;
                if f.kind == FrameKind::Directory {
                    return Some(f.body);
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), wait)
            .await
            .ok()?
    });
    let Some(body) = answer else {
        return fail(EXIT_RUNTIME, format!("le nœud ne répond pas sur {addr}"));
    };
    let nodes = cbor::from_slice::<Signed<Directory>>(&body, 1 << 20)
        .ok()
        .and_then(|d| verify_directory(&d, &roots, now()).ok());
    let Some(nodes) = nodes else {
        return fail(EXIT_RUNTIME, "annuaire invalide");
    };
    println!(
        "nœud {} : {} nœud(s) vérifié(s) jusqu'aux racines",
        &hex::encode(id)[..16],
        nodes.len()
    );
    for n in &nodes {
        let d = &n.descriptor;
        let sponsor = n
            .sponsor
            .map(|s| format!("parrain {}", &hex::encode(s)[..16]))
            .unwrap_or_else(|| "racine".into());
        let me = if d.id_pub == id { " (ce nœud)" } else { "" };
        println!(
            "  {}  {:<28} {}{}",
            &hex::encode(d.id_pub)[..16],
            d.endpoints.first().map(String::as_str).unwrap_or("-"),
            sponsor,
            me
        );
    }
    EXIT_OK
}

fn revoke(dir: &Path, node_id: &str) -> i32 {
    let node = match load(dir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    let Some(target) = hex::decode(node_id.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    else {
        return fail(EXIT_USAGE, "node_id : 64 caractères hexadécimaux attendus");
    };
    let r = Signed::sign(
        &node.keys.identity,
        &Revoke {
            v: DIR_VERSION,
            node_id: target,
            sponsor_id: node.keys.identity.public(),
            revoked_at: now(),
        },
    );
    let mut config = node.config.clone();
    config.revocations.push(hex::encode(cbor::to_vec(&r)));
    if let Err(e) = config.save(dir) {
        return fail(
            EXIT_RUNTIME,
            format!("écriture de {CONFIG_FILE} impossible : {e}"),
        );
    }
    println!("révocation de {} enregistrée", &node_id.trim()[..16]);
    println!(
        "→ redémarrez le nœud pour la publier ; elle n'est prise en compte que si ce nœud est le          parrain direct du nœud révoqué ou une racine (spec §4.3)"
    );
    EXIT_OK
}

fn init(dir: &Path, root: bool, endpoints: Vec<String>) -> i32 {
    let mut config = Config::default();
    config.node.root = root;
    config.node.public_endpoints = endpoints;
    if let Err(e) = config.validate() {
        return fail(EXIT_USAGE, e);
    }
    if dir.exists() && !dir.is_dir() {
        return fail(
            EXIT_USAGE,
            format!("{} n'est pas un répertoire", dir.display()),
        );
    }
    if dir.join(KEY_FILE).exists() || dir.join(CONFIG_FILE).exists() {
        return fail(
            EXIT_USAGE,
            format!(
                "{} contient déjà un nœud : rien n'a été modifié",
                dir.display()
            ),
        );
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        return fail(
            EXIT_RUNTIME,
            format!("création de {} impossible : {e}", dir.display()),
        );
    }
    let keys = NodeKeys::generate();
    if let Err(e) = keystore::save(dir, &keys) {
        return fail(EXIT_USAGE, e);
    }
    let write = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(CONFIG_FILE))
        .and_then(|mut f| std::io::Write::write_all(&mut f, config.to_toml().as_bytes()));
    if let Err(e) = write {
        return fail(
            EXIT_RUNTIME,
            format!("écriture de {CONFIG_FILE} impossible : {e}"),
        );
    }

    let id = keys.identity.public();
    println!("nœud initialisé dans {}", dir.display());
    println!("id: {}", hex::encode(id));
    if root {
        if config.node.public_endpoints.is_empty() {
            println!(
                "attention : aucune adresse publique (--endpoint) ; l'entrée d'amorçage ne sera \
                 utilisable qu'une fois une adresse ajoutée dans {CONFIG_FILE}"
            );
        } else {
            let entry = RootEntry {
                id_pub: id,
                endpoints: config.node.public_endpoints.clone(),
            };
            println!("bootstrap-entry: {}", hex::encode(cbor::to_vec(&entry)));
            println!(
                "→ cette entrée (clé publique + adresses) est à intégrer dans le bloc d'amorçage \
                 de l'application (spec §4.4). Elle ne contient aucun secret."
            );
        }
    } else {
        println!(
            "→ ce nœud doit être parrainé : utilisez plutôt `harpochat-server join <jeton>` sur un \
             répertoire vide, ou ajoutez à la main [[roots]] et node.chain dans {CONFIG_FILE}"
        );
    }
    EXIT_OK
}

fn load(dir: &Path) -> Result<Node, i32> {
    Node::load(dir, now()).map_err(|e| {
        let code = match e {
            NodeError::Config(_) => EXIT_USAGE,
            _ => EXIT_RUNTIME,
        };
        fail(code, e)
    })
}

fn summary(node: &Node) -> String {
    let id = hex::encode(node.keys.identity.public());
    let roles: Vec<String> = node
        .config
        .node
        .roles
        .iter()
        .map(|r| format!("{r:?}").to_lowercase())
        .collect();
    format!(
        "node {} roles={} root={} endpoints={}",
        &id[..16],
        roles.join(","),
        node.config.node.root,
        node.config.node.public_endpoints.len()
    )
}

/// Load and check a node the way `run --check` does.
fn prepare(dir: &Path) -> Result<Node, i32> {
    let node = load(dir)?;
    let t = now();
    if let Err(e) = node
        .descriptor(t)
        .verify()
        .and_then(|d| descriptor::validate(&d, t))
    {
        return Err(fail(EXIT_RUNTIME, format!("descripteur invalide : {e}")));
    }
    if node.config.node.public_endpoints.is_empty() {
        eprintln!("attention : aucune adresse publique, le nœud ne sera pas joignable");
    }
    if !node.config.node.root && node.chain().is_empty() {
        eprintln!(
            "attention : ce nœud n'est pas parrainé (node.chain vide) : ni les apps ni les \
             autres nœuds ne l'accepteront ; utilisez `harpochat-server join <jeton>`"
        );
    }
    if !crate::server::self_check(&node, t) {
        return Err(fail(
            EXIT_RUNTIME,
            "l'annuaire signé par ce nœud ne se vérifie pas",
        ));
    }
    Ok(node)
}

fn run(dir: &Path, check: bool, service: bool) -> i32 {
    let node = match prepare(dir) {
        Ok(n) => n,
        Err(code) => return code,
    };
    if check {
        println!("ok: {}", summary(&node));
        return EXIT_OK;
    }
    if service {
        #[cfg(windows)]
        return crate::winservice::run(node);
        #[cfg(not(windows))]
        return fail(EXIT_USAGE, "--service n'existe que sous Windows");
    }
    serve_until(node, async {
        let _ = tokio::signal::ctrl_c().await;
    })
}

/// Serve `node` until `shutdown` resolves; returns the exit code. All state
/// lives in RAM and is dropped on return.
pub fn serve_until(node: Node, shutdown: impl std::future::Future<Output = ()>) -> i32 {
    init_logging();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fail(EXIT_RUNTIME, format!("runtime : {e}")),
    };
    let addr = node.config.listen.addr.clone();
    let summary = summary(&node);
    rt.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => return fail(EXIT_RUNTIME, format!("écoute sur {addr} impossible : {e}")),
        };
        tracing::info!("harpochat-server démarré ({summary}), écoute sur {addr}");
        let r = crate::server::serve(node, listener, crate::router::system_clock(), shutdown).await;
        tracing::info!("arrêt : état en mémoire effacé");
        match r {
            Ok(()) => EXIT_OK,
            Err(e) => fail(EXIT_RUNTIME, e),
        }
    })
}

#[cfg(windows)]
fn service(dir: &Path, action: ServiceAction) -> i32 {
    match action {
        ServiceAction::Install => {
            if let Err(code) = prepare(dir) {
                return code;
            }
            match crate::winservice::install(dir) {
                Ok(()) => {
                    println!(
                        "service « {} » installé (démarrage automatique), données : {}",
                        crate::winservice::SERVICE_NAME,
                        crate::winservice::describe(dir).display()
                    );
                    println!(
                        "→ démarrez-le : sc.exe start {}",
                        crate::winservice::SERVICE_NAME
                    );
                    EXIT_OK
                }
                Err(e) => fail(EXIT_RUNTIME, e),
            }
        }
        ServiceAction::Uninstall => match crate::winservice::uninstall() {
            Ok(()) => {
                println!("service supprimé");
                EXIT_OK
            }
            Err(e) => fail(EXIT_RUNTIME, e),
        },
    }
}

#[cfg(not(windows))]
fn service(_dir: &Path, _action: ServiceAction) -> i32 {
    fail(
        EXIT_USAGE,
        "service Windows uniquement ; sous Linux, utilisez l'unité systemd fournie \
         (packaging/systemd/harpochat-server.service)",
    )
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("HARPOCHAT_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // No colour codes in files and journals.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .try_init();
}
