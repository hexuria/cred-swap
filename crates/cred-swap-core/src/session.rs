//! One conversation's substitutions, shared safely across threads.
//!
//! A [`Cloak`] belongs to one conversation and needs `&mut` to do anything, so
//! a server handling many conversations at once has to answer three questions
//! that have nothing to do with detection: where does each conversation's
//! state live, how do threads share it, and what happens when the process
//! restarts. This module answers them once, so every host does not answer them
//! again and differently.
//!
//! ```no_run
//! use cred_swap_core::session::SessionStore;
//! use cred_swap_core::{Policy, Style};
//!
//! let store = SessionStore::builder()
//!     .directory("/var/lib/my-server/cred-swap")
//!     .policy(Policy::default())
//!     .style(Style::Realistic)
//!     .secret(b"a secret this deployment holds")
//!     .build()?;
//!
//! // One handle per conversation. Cheap to make, safe to send between tasks.
//! let session = store.session("run:8f21c4")?;
//!
//! let outgoing = session.scrub("deploy failed on db.prod.internal")?;
//! let reply = send_to_model(&outgoing.text);
//! let readable = session.restore(&reply)?;
//! # fn send_to_model(_: &str) -> String { String::new() }
//! # Ok::<(), cred_swap_core::session::SessionError>(())
//! ```
//!
//! # Isolation between conversations
//!
//! Each session's generator is [derived](crate::Surrogates::derive) from the
//! store's root secret and the session id, so two conversations give the same
//! real value two different stand-ins. That matters on a shared server: with
//! one generator for everything, a stand-in appearing in one tenant's
//! transcript would identify that value in every other tenant's.
//!
//! # Locking
//!
//! Each session holds a [`std::sync::Mutex`]. Every method here acquires it,
//! does bounded CPU work, and releases it before returning — no lock is ever
//! held across an await point, so these are safe to call from async code. The
//! work is regex matching over one message, not I/O.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::detect::DetectorError;
use crate::engine::{Cloak, Decision, Replacement, Scrubbed};
use crate::fake::{Style, Surrogates};
use crate::json;
use crate::policy::Policy;
use crate::vault::{Entry, Vault, VaultError};

/// Something went wrong opening or using a session.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The policy contains a pattern that does not compile.
    #[error("the policy could not be compiled")]
    Policy(#[from] DetectorError),

    /// The session's stored state could not be read or written.
    #[error("session `{id}` could not be loaded or saved")]
    Storage {
        /// Which session.
        id: String,
        /// The underlying failure.
        #[source]
        source: VaultError,
    },

    /// No seed source: neither a secret nor a root generator was supplied,
    /// and this build has no operating system to ask.
    ///
    /// Only reachable in a build without the `os-rng` feature, such as a
    /// browser one. Supply [`SessionStoreBuilder::secret`] or
    /// [`SessionStoreBuilder::root`].
    #[error(
        "a session store needs a seed: call `secret` or `root` on the builder, \
         because this build cannot draw one from the operating system"
    )]
    NoSeed,

    /// A thread panicked while holding this session's lock.
    ///
    /// The session is not reused after that, because its vault may be half
    /// updated and scrubbing against a half-updated vault can send a real
    /// value onward. Drop the session with [`SessionStore::forget`] and open
    /// a fresh one.
    #[error("session `{id}` was left in an unknown state by an earlier panic")]
    Poisoned {
        /// Which session.
        id: String,
    },
}

/// Shared configuration and the live session map.
struct Inner {
    directory: Option<PathBuf>,
    policy: Policy,
    root: Surrogates,
    autosave: bool,
    sessions: RwLock<HashMap<String, Arc<Entry_>>>,
}

/// One conversation's state.
struct Entry_ {
    id: String,
    path: Option<PathBuf>,
    cloak: Mutex<Cloak>,
}

/// A registry of per-conversation [`Cloak`]s.
///
/// Cloning is cheap: every clone shares the same sessions.
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<Inner>,
}

impl fmt::Debug for SessionStore {
    /// Counts only. The contents are what is being protected.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let live = self.inner.sessions.read().map_or(0, |map| map.len());
        f.debug_struct("SessionStore")
            .field("live_sessions", &live)
            .field("persistent", &self.inner.directory.is_some())
            .finish_non_exhaustive()
    }
}

impl SessionStore {
    /// Start configuring a store.
    #[must_use]
    pub fn builder() -> SessionStoreBuilder {
        SessionStoreBuilder::default()
    }

    /// The handle for one conversation, opening it if this is the first use.
    ///
    /// `id` can be anything: a run id, a tenant and thread pair, a UUID. It is
    /// hashed to produce a filename, so it never reaches the filesystem
    /// literally and cannot escape the store directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the session's stored state exists but cannot be
    /// read, or if the policy does not compile.
    pub fn session(&self, id: impl Into<String>) -> Result<Session, SessionError> {
        let id = id.into();

        if let Ok(map) = self.inner.sessions.read()
            && let Some(found) = map.get(&id)
        {
            return Ok(Session {
                store: Arc::clone(&self.inner),
                entry: Arc::clone(found),
            });
        }

        let opened = Arc::new(self.open(&id)?);
        let entry = match self.inner.sessions.write() {
            Ok(mut map) => Arc::clone(map.entry(id).or_insert(opened)),
            // A poisoned registry only means some other thread panicked while
            // inserting. The map itself is a plain HashMap and is still sound,
            // so use the session we just opened rather than failing the call.
            Err(_) => opened,
        };

        Ok(Session {
            store: Arc::clone(&self.inner),
            entry,
        })
    }

    fn open(&self, id: &str) -> Result<Entry_, SessionError> {
        let path = self
            .inner
            .directory
            .as_ref()
            .map(|dir| dir.join(format!("{}.json", filename_for(id))));

        let surrogates = self.inner.root.derive(id);
        let vault = match &path {
            Some(path) => {
                Vault::load_or_new(path, surrogates).map_err(|source| SessionError::Storage {
                    id: id.to_owned(),
                    source,
                })?
            }
            None => Vault::new(surrogates),
        };

        Ok(Entry_ {
            id: id.to_owned(),
            path,
            cloak: Mutex::new(Cloak::resume(self.inner.policy.clone(), vault)?),
        })
    }

    /// Write every live session to disk.
    ///
    /// Call this on shutdown. With `autosave` on, it is otherwise unnecessary.
    ///
    /// # Errors
    ///
    /// Returns the first storage failure. Sessions after it are still
    /// attempted, so one unwritable file does not strand the rest.
    pub fn persist_all(&self) -> Result<(), SessionError> {
        let Ok(map) = self.inner.sessions.read() else {
            return Ok(());
        };
        let mut first_error = None;
        for entry in map.values() {
            if let Err(error) = save(entry)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Drop a session from memory, after writing it out.
    ///
    /// Its stored state stays on disk, so opening the same id again resumes
    /// where it left off. Use this to bound memory on a long-running server.
    ///
    /// # Errors
    ///
    /// Returns an error if the session could not be written before dropping.
    pub fn forget(&self, id: &str) -> Result<(), SessionError> {
        let removed = self
            .inner
            .sessions
            .write()
            .ok()
            .and_then(|mut map| map.remove(id));
        match removed {
            Some(entry) => save(&entry),
            None => Ok(()),
        }
    }

    /// Delete a session's stored state as well as dropping it.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be removed.
    pub fn destroy(&self, id: &str) -> Result<(), SessionError> {
        let _ = self
            .inner
            .sessions
            .write()
            .ok()
            .and_then(|mut map| map.remove(id));

        if let Some(dir) = &self.inner.directory {
            let path = dir.join(format!("{}.json", filename_for(id)));
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(SessionError::Storage {
                        id: id.to_owned(),
                        source: VaultError::Io {
                            path: path.display().to_string(),
                            source,
                        },
                    });
                }
            }
        }
        Ok(())
    }

    /// How many sessions are currently held in memory.
    #[must_use]
    pub fn live(&self) -> usize {
        self.inner.sessions.read().map_or(0, |map| map.len())
    }
}

/// A handle to one conversation.
///
/// Cheap to clone and safe to send between threads and tasks. Two handles for
/// the same id share one vault, so substitutions made through either are
/// visible to both.
#[derive(Clone)]
pub struct Session {
    store: Arc<Inner>,
    entry: Arc<Entry_>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.entry.id)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The id this session was opened with.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.entry.id
    }

    /// Replace sensitive values in text with stand-ins.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn scrub(&self, text: &str) -> Result<Scrubbed, SessionError> {
        self.with(|cloak| cloak.scrub(text))
    }

    /// Replace sensitive values, asking `decide` about each finding.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn scrub_with(
        &self,
        text: &str,
        decide: impl FnMut(&crate::detect::Finding) -> Decision,
    ) -> Result<Scrubbed, SessionError> {
        self.with(|cloak| cloak.scrub_with(text, decide))
    }

    /// Report what would be replaced, changing nothing.
    ///
    /// Nothing is written to the vault, so showing a user what is about to be
    /// sent leaves no trace if they abandon the message.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn inspect(&self, text: &str) -> Result<Vec<crate::detect::Finding>, SessionError> {
        self.with_ref(|cloak| cloak.inspect(text))
    }

    /// Put the real values back wherever a stand-in appears.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn restore(&self, text: &str) -> Result<String, SessionError> {
        self.with(|cloak| cloak.restore(text))
    }

    /// Restore a growing buffer, holding back what might still be incomplete.
    ///
    /// Returns the text to emit and how many bytes it consumed. Keep the
    /// remainder and prepend it to the next chunk. Use this for a streamed
    /// reply, where restoring eagerly would cut a stand-in in half.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn restore_streaming(&self, text: &str) -> Result<(String, usize), SessionError> {
        self.with(|cloak| cloak.restore_streaming(text))
    }

    /// Scrub every string in a JSON document, in place.
    ///
    /// This is the one to use on a provider request body: it reaches the
    /// system prompt, every message, every content block and every tool result
    /// without knowing the provider's schema.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn scrub_json(&self, value: &mut Value) -> Result<Vec<Replacement>, SessionError> {
        self.with(|cloak| {
            let mut changes = json::Changes::default();
            json::scrub_value(cloak, value, &mut changes);
            changes.replacements
        })
    }

    /// Restore every string in a JSON document, in place.
    ///
    /// Run this over a tool call's arguments before executing the tool. A
    /// model that was shown a stand-in hostname will ask you to connect to the
    /// stand-in; without this the agent dutifully tries, and fails, against a
    /// host that does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn restore_json(&self, value: &mut Value) -> Result<(), SessionError> {
        self.with(|cloak| json::restore_value(cloak, value))
    }

    /// Every substitution this session has made.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn entries(&self) -> Result<Vec<Entry>, SessionError> {
        self.with_ref(|cloak| cloak.vault().entries().to_vec())
    }

    /// Write this session to disk now.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn persist(&self) -> Result<(), SessionError> {
        save(&self.entry)
    }

    /// Serialize this session, for a host that stores state its own way.
    ///
    /// # Errors
    ///
    /// Returns an error if a previous call panicked while holding the lock.
    pub fn export(&self) -> Result<String, SessionError> {
        self.with_ref(|cloak| cloak.vault().to_json())
    }

    /// Run `work` against the cloak, saving afterwards if autosave is on.
    fn with<T>(&self, work: impl FnOnce(&mut Cloak) -> T) -> Result<T, SessionError> {
        let outcome = {
            let mut guard = self.entry.cloak.lock().map_err(self.poisoned())?;
            work(&mut guard)
        };
        if self.store.autosave {
            save(&self.entry)?;
        }
        Ok(outcome)
    }

    /// Run `work` against the cloak without saving, for read-only calls.
    fn with_ref<T>(&self, work: impl FnOnce(&Cloak) -> T) -> Result<T, SessionError> {
        let guard = self.entry.cloak.lock().map_err(self.poisoned())?;
        Ok(work(&guard))
    }

    fn poisoned<T>(&self) -> impl Fn(PoisonError<T>) -> SessionError + '_ {
        move |_| SessionError::Poisoned {
            id: self.entry.id.clone(),
        }
    }
}

fn save(entry: &Entry_) -> Result<(), SessionError> {
    let Some(path) = &entry.path else {
        return Ok(());
    };
    let guard = entry.cloak.lock().map_err(|_| SessionError::Poisoned {
        id: entry.id.clone(),
    })?;
    guard
        .vault()
        .save(path)
        .map_err(|source| SessionError::Storage {
            id: entry.id.clone(),
            source,
        })
}

/// A filesystem-safe name for an arbitrary session id.
///
/// Hashed rather than sanitized, so an id containing a path separator, a
/// newline or a `..` cannot reach outside the store directory, and two ids
/// that sanitize to the same string do not collide.
fn filename_for(id: &str) -> String {
    use std::fmt::Write as _;
    let mut hasher = Sha256::new();
    hasher.update(b"cred-swap/session-file/v1");
    hasher.update(id.as_bytes());
    hasher
        .finalize()
        .iter()
        .take(16)
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Builds a [`SessionStore`].
pub struct SessionStoreBuilder {
    directory: Option<PathBuf>,
    policy: Policy,
    style: Style,
    root: Option<Surrogates>,
    autosave: bool,
}

impl Default for SessionStoreBuilder {
    fn default() -> Self {
        Self {
            directory: None,
            policy: Policy::default(),
            style: Style::Realistic,
            root: None,
            autosave: true,
        }
    }
}

impl SessionStoreBuilder {
    /// Keep sessions in this directory, so they survive a restart.
    ///
    /// Without one, sessions live only in memory and a restart makes every
    /// stand-in already sent to a model unrestorable.
    #[must_use]
    pub fn directory(mut self, path: impl AsRef<Path>) -> Self {
        self.directory = Some(path.as_ref().to_path_buf());
        self
    }

    /// The rules to apply.
    #[must_use]
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// What stand-ins should look like.
    #[must_use]
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Derive every session's generator from this secret.
    ///
    /// Use a stable per-deployment secret, kept wherever the deployment keeps
    /// its other secrets. It is what makes a session's stand-ins reproducible
    /// across restarts, and it must not be guessable: anyone who knows it can
    /// regenerate a stand-in from a real value and confirm the value was
    /// present.
    #[must_use]
    pub fn secret(mut self, secret: &[u8]) -> Self {
        self.root = Some(Surrogates::from_secret(secret, self.style));
        self
    }

    /// Use this generator as the root instead of deriving one from a secret.
    #[must_use]
    pub fn root(mut self, root: Surrogates) -> Self {
        self.root = Some(root);
        self
    }

    /// Whether to write a session out after every change.
    ///
    /// On by default. Turning it off is faster and means a crash can strand
    /// stand-ins that a model has already been shown.
    #[must_use]
    pub const fn autosave(mut self, autosave: bool) -> Self {
        self.autosave = autosave;
        self
    }

    /// Build the store.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy contains a pattern that does not
    /// compile, so a bad configuration fails at startup rather than on the
    /// first message.
    pub fn build(self) -> Result<SessionStore, SessionError> {
        // Compile the policy once here purely to fail fast.
        crate::detect::Detector::new(self.policy.clone())?;

        let style = self.style;
        let root = match self.root {
            Some(root) if root.style() == style => root,
            Some(root) => Surrogates::from_seed(*root.seed(), style),
            // Without a seed source there is nothing safe to fall back to. A
            // fixed default would make every deployment's stand-ins
            // reproducible by anyone holding this crate.
            #[cfg(feature = "os-rng")]
            None => Surrogates::random(style),
            #[cfg(not(feature = "os-rng"))]
            None => return Err(SessionError::NoSeed),
        };

        Ok(SessionStore {
            inner: Arc::new(Inner {
                directory: self.directory,
                policy: self.policy,
                root,
                autosave: self.autosave,
                sessions: RwLock::new(HashMap::new()),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityKind;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "cred-swap-session-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn memory_store() -> SessionStore {
        SessionStore::builder()
            .secret(b"session tests")
            .build()
            .unwrap()
    }

    #[test]
    fn one_session_is_consistent_across_calls() {
        let store = memory_store();
        let session = store.session("run-1").unwrap();

        let first = session.scrub("mail dana@corp.com").unwrap();
        let second = session.scrub("dana@corp.com again").unwrap();
        assert_eq!(first.replacements[0].fake, second.replacements[0].fake);
        assert_eq!(session.restore(&first.text).unwrap(), "mail dana@corp.com");
    }

    #[test]
    fn two_handles_for_one_id_share_a_vault() {
        let store = memory_store();
        let a = store.session("run-1").unwrap();
        let b = store.session("run-1").unwrap();

        let scrubbed = a.scrub("mail dana@corp.com").unwrap();
        assert_eq!(
            b.restore(&scrubbed.text).unwrap(),
            "mail dana@corp.com",
            "the second handle could not see the first handle's substitutions"
        );
        assert_eq!(store.live(), 1);
    }

    #[test]
    fn separate_conversations_do_not_share_stand_ins() {
        let store = memory_store();
        let left = store
            .session("run-1")
            .unwrap()
            .scrub("dana@corp.com")
            .unwrap();
        let right = store
            .session("run-2")
            .unwrap()
            .scrub("dana@corp.com")
            .unwrap();

        assert_ne!(
            left.replacements[0].fake, right.replacements[0].fake,
            "one conversation's stand-in identified the value in another"
        );

        // And one cannot restore the other's.
        let crossed = store.session("run-2").unwrap().restore(&left.text).unwrap();
        assert_eq!(crossed, left.text);
    }

    #[test]
    fn a_session_survives_a_restart() {
        let dir = TempDir::new("restart");
        let build = || {
            SessionStore::builder()
                .directory(&dir.0)
                .secret(b"stable deployment secret")
                .build()
                .unwrap()
        };

        let sent = {
            let store = build();
            let session = store.session("run-1").unwrap();
            let scrubbed = session.scrub("mail dana@corp.com").unwrap();
            store.persist_all().unwrap();
            scrubbed.text
        };

        // A brand new store, as after a process restart.
        let store = build();
        let session = store.session("run-1").unwrap();
        assert_eq!(session.restore(&sent).unwrap(), "mail dana@corp.com");
    }

    #[test]
    fn an_id_with_path_separators_cannot_escape_the_directory() {
        let dir = TempDir::new("traversal");
        let store = SessionStore::builder()
            .directory(&dir.0)
            .secret(b"s")
            .build()
            .unwrap();

        let hostile = "../../../../etc/passwd";
        let session = store.session(hostile).unwrap();
        session.scrub("mail dana@corp.com").unwrap();
        session.persist().unwrap();

        let written: Vec<_> = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(written.len(), 1, "{written:?}");
        assert!(!written[0].contains(".."), "{written:?}");
        assert!(
            std::path::Path::new(&written[0])
                .extension()
                .is_some_and(|ext| ext == "json"),
            "{written:?}"
        );
        // The id is still usable and still itself.
        assert_eq!(session.id(), hostile);
    }

    #[test]
    fn two_ids_that_look_alike_do_not_collide() {
        let dir = TempDir::new("collide");
        let store = SessionStore::builder()
            .directory(&dir.0)
            .secret(b"s")
            .build()
            .unwrap();

        for id in ["a/b", "a:b", "a b", "a_b"] {
            store.session(id).unwrap().scrub("dana@corp.com").unwrap();
        }
        let count = std::fs::read_dir(&dir.0).unwrap().count();
        assert_eq!(count, 4, "ids collided on disk");
    }

    #[test]
    fn json_round_trips_through_a_session() {
        let store = memory_store();
        let session = store.session("run-1").unwrap();

        let mut body = serde_json::json!({
            "model": "claude-fable-5-1",
            "messages": [
                {"role": "user", "content": [
                    {"type": "text", "text": "ssh into db.prod.internal as dana@corp.com"}
                ]}
            ]
        });

        let replacements = session.scrub_json(&mut body).unwrap();
        assert!(!replacements.is_empty());
        let rendered = body.to_string();
        assert!(!rendered.contains("dana@corp.com"), "{rendered}");
        assert_eq!(
            body["model"], "claude-fable-5-1",
            "a structural field changed"
        );

        session.restore_json(&mut body).unwrap();
        assert_eq!(
            body["messages"][0]["content"][0]["text"],
            "ssh into db.prod.internal as dana@corp.com"
        );
    }

    #[test]
    fn a_tool_call_argument_is_restored_before_it_would_run() {
        let store = memory_store();
        let session = store.session("run-1").unwrap();

        // The model is shown a stand-in host.
        let scrubbed = session.scrub("check the logs on db.prod.internal").unwrap();
        let stand_in = scrubbed.replacements[0].fake.clone();

        // So it asks to connect to the stand-in.
        let mut call = serde_json::json!({
            "name": "ssh",
            "arguments": {"host": stand_in, "command": "tail -n 50 app.log"}
        });

        session.restore_json(&mut call).unwrap();
        assert_eq!(
            call["arguments"]["host"], "db.prod.internal",
            "the tool would have run against a host that does not exist"
        );
        assert_eq!(call["name"], "ssh");
    }

    #[test]
    fn inspect_does_not_record_anything() {
        let store = memory_store();
        let session = store.session("run-1").unwrap();

        let findings = session.inspect("mail dana@corp.com").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, EntityKind::EmailAddress);
        assert!(session.entries().unwrap().is_empty());
    }

    #[test]
    fn forget_frees_memory_but_keeps_the_conversation() {
        let dir = TempDir::new("forget");
        let store = SessionStore::builder()
            .directory(&dir.0)
            .secret(b"s")
            .build()
            .unwrap();

        let sent = store
            .session("run-1")
            .unwrap()
            .scrub("mail dana@corp.com")
            .unwrap()
            .text;
        assert_eq!(store.live(), 1);

        store.forget("run-1").unwrap();
        assert_eq!(store.live(), 0);

        // Reopening resumes from disk.
        assert_eq!(
            store.session("run-1").unwrap().restore(&sent).unwrap(),
            "mail dana@corp.com"
        );
    }

    #[test]
    fn destroy_removes_the_stored_state() {
        let dir = TempDir::new("destroy");
        let store = SessionStore::builder()
            .directory(&dir.0)
            .secret(b"s")
            .build()
            .unwrap();

        store
            .session("run-1")
            .unwrap()
            .scrub("dana@corp.com")
            .unwrap();
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);

        store.destroy("run-1").unwrap();
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
        store
            .destroy("run-1")
            .expect("destroying twice is not an error");
    }

    #[cfg(not(feature = "os-rng"))]
    #[test]
    fn a_build_without_os_entropy_demands_a_seed() {
        let error = SessionStore::builder().build().unwrap_err();
        assert!(matches!(error, SessionError::NoSeed));
    }

    #[test]
    fn a_bad_policy_fails_at_startup_not_on_the_first_message() {
        let mut policy = Policy::default();
        policy.custom_patterns.push(crate::policy::CustomPattern {
            label: "broken".into(),
            pattern: "ACME-[0-9".into(),
            group: 0,
        });
        let error = SessionStore::builder()
            .policy(policy)
            .secret(b"s")
            .build()
            .unwrap_err();
        assert!(matches!(error, SessionError::Policy(_)));
    }

    #[test]
    fn sessions_are_usable_from_many_threads_at_once() {
        let store = memory_store();
        let mut handles = Vec::new();

        for worker in 0..8 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                // Two workers per conversation, so they contend for one lock.
                let session = store.session(format!("run-{}", worker % 4)).unwrap();
                for _ in 0..50 {
                    let scrubbed = session.scrub("mail dana@corp.com").unwrap();
                    assert_eq!(
                        session.restore(&scrubbed.text).unwrap(),
                        "mail dana@corp.com"
                    );
                }
            }));
        }
        for handle in handles {
            handle.join().expect("a worker panicked");
        }

        assert_eq!(store.live(), 4);
        for conversation in 0..4 {
            let session = store.session(format!("run-{conversation}")).unwrap();
            assert_eq!(
                session.entries().unwrap().len(),
                1,
                "concurrent use minted more than one stand-in for one value"
            );
        }
    }

    #[test]
    fn debug_output_does_not_leak_contents() {
        let store = memory_store();
        let session = store.session("run-1").unwrap();
        session.scrub("mail dana@corp.com").unwrap();

        assert!(!format!("{store:?}").contains("dana"));
        assert!(!format!("{session:?}").contains("dana"));
    }
}
