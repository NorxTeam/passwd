#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use norx_userdb::{
    atomic_replace, AtomicStorage, Database, PasswordChangeError, PasswordHasher, PasswordPolicy,
    PasswordVerifier, RecoveryState, SessionCredentials, StorageError, CAP_ACCOUNT_ADMIN,
};

pub const MAX_AUDIT_EVENTS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Change,
    Reset,
    Lock,
    Unlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub operation: Operation,
    pub target_uid: u32,
    pub success: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswdError {
    PermissionDenied,
    InvalidInput,
    PolicyRejected,
    HashUnavailable,
    StorageUnavailable,
    StorageBusy,
    StorageCorrupt,
    CommittedButUnlockFailed,
}

pub struct PasswdEngine {
    policy: PasswordPolicy,
    audit: Vec<AuditEvent>,
}

impl PasswdEngine {
    pub fn new(policy: PasswordPolicy) -> Result<Self, PasswdError> {
        if policy.min_length == 0
            || policy.min_length > policy.max_length
            || policy.max_length > norx_userdb::MAX_PASSWORD_BYTES
        {
            return Err(PasswdError::PolicyRejected);
        }
        Ok(Self {
            policy,
            audit: Vec::new(),
        })
    }

    pub const fn policy(&self) -> PasswordPolicy {
        self.policy
    }

    pub fn audit(&self) -> &[AuditEvent] {
        &self.audit
    }

    pub fn change_password<V: PasswordVerifier, H: PasswordHasher>(
        &mut self,
        database: &mut Database,
        actor: SessionCredentials,
        target_uid: u32,
        old_password: Option<&[u8]>,
        new_password: &[u8],
        confirmation: &[u8],
        verifier: &V,
        hasher: &H,
    ) -> Result<(), PasswdError> {
        let operation = if actor.has_capability(CAP_ACCOUNT_ADMIN) {
            Operation::Reset
        } else {
            Operation::Change
        };
        let result = database.change_password(
            actor,
            target_uid,
            old_password,
            new_password,
            confirmation,
            self.policy,
            verifier,
            hasher,
        );
        self.record(operation, target_uid, result.is_ok());
        result.map_err(map_password_error)
    }

    pub fn set_locked(
        &mut self,
        database: &mut Database,
        actor: SessionCredentials,
        target_uid: u32,
        locked: bool,
    ) -> Result<(), PasswdError> {
        let result = database.set_locked(actor, target_uid, locked);
        self.record(
            if locked {
                Operation::Lock
            } else {
                Operation::Unlock
            },
            target_uid,
            result.is_ok(),
        );
        result.map_err(|_| PasswdError::PermissionDenied)
    }

    pub fn commit<S: AtomicStorage>(
        &self,
        storage: &mut S,
        committed_path: &[u8],
        temp_path: &[u8],
        database: &Database,
    ) -> Result<(), PasswdError> {
        atomic_replace(storage, committed_path, temp_path, database).map_err(map_storage_error)
    }

    pub fn recover<S: AtomicStorage>(
        &self,
        storage: &mut S,
        committed_path: &[u8],
        temp_path: &[u8],
    ) -> Result<(Database, RecoveryState), PasswdError> {
        norx_userdb::load_with_recovery(storage, committed_path, temp_path)
            .map_err(map_storage_error)
    }

    fn record(&mut self, operation: Operation, target_uid: u32, success: bool) {
        if self.audit.len() == MAX_AUDIT_EVENTS {
            self.audit.remove(0);
        }
        self.audit.push(AuditEvent {
            operation,
            target_uid,
            success,
        });
    }
}

fn map_password_error(error: PasswordChangeError) -> PasswdError {
    match error {
        PasswordChangeError::Denied
        | PasswordChangeError::NotFound
        | PasswordChangeError::OldPasswordRejected => PasswdError::PermissionDenied,
        PasswordChangeError::ConfirmationMismatch
        | PasswordChangeError::PasswordReuse
        | PasswordChangeError::InvalidPassword
        | PasswordChangeError::InvalidPolicy => PasswdError::PolicyRejected,
        PasswordChangeError::HashFailed | PasswordChangeError::InvalidHash => {
            PasswdError::HashUnavailable
        }
    }
}

fn map_storage_error(error: StorageError) -> PasswdError {
    match error {
        StorageError::Busy => PasswdError::StorageBusy,
        StorageError::Corrupt => PasswdError::StorageCorrupt,
        StorageError::CommittedButUnlockFailed => PasswdError::CommittedButUnlockFailed,
        StorageError::Missing | StorageError::Unavailable | StorageError::TooLarge => {
            PasswdError::StorageUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    const HASH: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    const NEW_HASH: &str =
        "$argon2id$v=19$m=65536,t=3,p=1$bmV3LXNhbHQtdmFsdWUhIQ$bmV3LWRpZ2VzdC12YWx1ZS0wMTIzNDU2Nzg5YWJjZGU";
    const DATABASE: &[u8] = b"NORX-USERDB 1\nu:alice:1000:1000:0:0:/users/alice:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY\ng:users:1000:alice\n";

    struct Verifier;
    impl PasswordVerifier for Verifier {
        fn verify(&self, password: &[u8], encoded_hash: &[u8]) -> bool {
            password == b"oldpass!" && encoded_hash == HASH
        }
    }

    struct Hasher;
    impl PasswordHasher for Hasher {
        fn hash(&self, password: &[u8]) -> Option<String> {
            (password == b"newpass!").then(|| NEW_HASH.into())
        }
    }

    #[test]
    fn engine_maps_policy_permissions_and_redacted_audit() {
        let mut database = Database::parse(DATABASE).unwrap();
        let user = database.lookup_user(b"alice").unwrap();
        let actor = SessionCredentials::from_user(&user);
        let mut engine = PasswdEngine::new(PasswordPolicy::DEFAULT).unwrap();
        assert_eq!(
            engine.change_password(
                &mut database,
                actor,
                1000,
                Some(b"wrong"),
                b"newpass!",
                b"newpass!",
                &Verifier,
                &Hasher,
            ),
            Err(PasswdError::PermissionDenied)
        );
        assert_eq!(
            engine.change_password(
                &mut database,
                actor,
                1000,
                Some(b"oldpass!"),
                b"short",
                b"short",
                &Verifier,
                &Hasher,
            ),
            Err(PasswdError::PolicyRejected)
        );
        engine
            .change_password(
                &mut database,
                actor,
                1000,
                Some(b"oldpass!"),
                b"newpass!",
                b"newpass!",
                &Verifier,
                &Hasher,
            )
            .unwrap();
        let audit = alloc::format!("{:?}", engine.audit());
        assert!(!audit.contains("oldpass!") && !audit.contains(NEW_HASH));
        assert_eq!(engine.audit().len(), 3);
    }

    #[test]
    fn policy_boundaries_are_rejected_without_unbounded_input() {
        assert!(PasswdEngine::new(PasswordPolicy {
            min_length: 0,
            max_length: 8,
        })
        .is_err());
        assert!(PasswdEngine::new(PasswordPolicy {
            min_length: 8,
            max_length: 129,
        })
        .is_err());
    }

    #[test]
    fn commit_propagates_committed_but_unlock_failed_for_reconciliation() {
        struct Storage {
            committed: Option<Vec<u8>>,
            temporary: Option<Vec<u8>>,
            locked: bool,
            fail_unlock: bool,
        }

        impl AtomicStorage for Storage {
            fn read(&mut self, path: &[u8], output: &mut Vec<u8>) -> Result<(), StorageError> {
                let source = if path == b"tmp" {
                    self.temporary.as_ref()
                } else {
                    self.committed.as_ref()
                }
                .ok_or(StorageError::Missing)?;
                output.extend_from_slice(source);
                Ok(())
            }

            fn lock(&mut self) -> Result<(), StorageError> {
                if self.locked {
                    Err(StorageError::Busy)
                } else {
                    self.locked = true;
                    Ok(())
                }
            }

            fn write_temp(&mut self, _path: &[u8], contents: &[u8]) -> Result<(), StorageError> {
                self.temporary = Some(contents.to_vec());
                Ok(())
            }

            fn sync_file(&mut self, _path: &[u8]) -> Result<(), StorageError> {
                Ok(())
            }

            fn replace(
                &mut self,
                _temp_path: &[u8],
                _committed_path: &[u8],
            ) -> Result<(), StorageError> {
                self.committed = self.temporary.take();
                Ok(())
            }

            fn sync_parent(&mut self, _committed_path: &[u8]) -> Result<(), StorageError> {
                Ok(())
            }

            fn unlock(&mut self) -> Result<(), StorageError> {
                if self.fail_unlock {
                    return Err(StorageError::Unavailable);
                }
                self.locked = false;
                Ok(())
            }
        }

        let database = Database::parse(DATABASE).unwrap();
        let mut storage = Storage {
            committed: Some(DATABASE.to_vec()),
            temporary: None,
            locked: false,
            fail_unlock: true,
        };
        let engine = PasswdEngine::new(PasswordPolicy::DEFAULT).unwrap();
        assert_eq!(
            engine.commit(&mut storage, b"db", b"tmp", &database),
            Err(PasswdError::CommittedButUnlockFailed)
        );
        let (reloaded, state) = engine.recover(&mut storage, b"db", b"tmp").unwrap();
        assert_eq!(state, RecoveryState::Current);
        assert_eq!(reloaded, database);
        storage.fail_unlock = false;
        storage.unlock().unwrap();
    }
}
