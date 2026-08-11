#![feature(alloc_error_handler)]
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::Layout;
use core::panic::PanicInfo;
use norx_passwd::{PasswdEngine, PasswdError};
use norx_userdb::{
    AtomicStorage, Database, PasswordHasher, PasswordVerifier, RecoveryState, SessionCredentials,
    StorageError, CAP_ACCOUNT_ADMIN,
};
use userspace::syscall;

const HASH: &[u8] = b"$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ";
const NEW_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$bmV3c2FsdFNhbXBsZQ$bmV3ZGlnaWVzdFNhbXBsZQ";
const RESET_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=1$cmVzZXRzYW1wbGU$cmVzZXRkaWdlc3Q";
const SEED: &[u8] = b"NORX-USERDB 1\nu:root:0:0:0:256:/root:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ\nu:alice:1000:1000:0:0:/users/alice:/bin/nsh:$argon2id$v=19$m=65536,t=3,p=1$c2FsdFNhbXBsZQ$ZGlnaWVzdFNhbXBsZQ\ng:users:1000:alice\n";

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    syscall::exit(101)
}

#[alloc_error_handler]
fn allocation_error(_layout: Layout) -> ! {
    syscall::exit(12)
}

struct FixtureVerifier;

impl PasswordVerifier for FixtureVerifier {
    fn verify(&self, password: &[u8], encoded_hash: &[u8]) -> bool {
        (encoded_hash == HASH && password == b"oldpass!")
            || (encoded_hash == NEW_HASH.as_bytes() && password == b"newpass!")
            || (encoded_hash == RESET_HASH.as_bytes() && password == b"resetpass!")
    }
}

struct FixtureHasher;

impl PasswordHasher for FixtureHasher {
    fn hash(&self, password: &[u8]) -> Option<alloc::string::String> {
        if password == b"newpass!" {
            Some(NEW_HASH.into())
        } else if password == b"resetpass!" {
            Some(RESET_HASH.into())
        } else {
            None
        }
    }
}

#[derive(Default)]
struct MemoryStorage {
    committed: Option<Vec<u8>>,
    temporary: Option<Vec<u8>>,
    locked: bool,
}

impl AtomicStorage for MemoryStorage {
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

    fn replace(&mut self, _temp_path: &[u8], _committed_path: &[u8]) -> Result<(), StorageError> {
        self.committed = self.temporary.take();
        Ok(())
    }

    fn sync_parent(&mut self, _committed_path: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }

    fn unlock(&mut self) -> Result<(), StorageError> {
        self.locked = false;
        Ok(())
    }
}

fn write_all(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let Ok(written) = syscall::write(1, bytes[offset..].as_ptr(), bytes.len() - offset) else {
            return false;
        };
        if written == 0 {
            return false;
        }
        offset += written;
    }
    true
}

fn marker(bytes: &[u8]) -> bool {
    write_all(bytes)
}

fn run() -> bool {
    let Ok(mut database) = Database::parse(SEED) else {
        return false;
    };
    let alice = SessionCredentials::from_user(&database.lookup_user(b"alice").unwrap());
    let root = SessionCredentials {
        capabilities: CAP_ACCOUNT_ADMIN,
        ..SessionCredentials::from_user(&database.lookup_user(b"root").unwrap())
    };
    let mut engine = PasswdEngine::new(norx_userdb::PasswordPolicy::DEFAULT).unwrap();

    if engine.change_password(
        &mut database,
        alice,
        1000,
        Some(b"wrongold"),
        b"newpass!",
        b"newpass!",
        &FixtureVerifier,
        &FixtureHasher,
    ) != Err(PasswdError::PermissionDenied)
        || !marker(b"PASSWD:WRONG_OLD_DENIED\n")
    {
        return false;
    }
    if engine.change_password(
        &mut database,
        alice,
        1000,
        Some(b"oldpass!"),
        b"newpass!",
        b"different!",
        &FixtureVerifier,
        &FixtureHasher,
    ) != Err(PasswdError::PolicyRejected)
        || !marker(b"PASSWD:CONFIRMATION_DENIED\n")
    {
        return false;
    }
    if engine.change_password(
        &mut database,
        alice,
        1000,
        Some(b"oldpass!"),
        b"short",
        b"short",
        &FixtureVerifier,
        &FixtureHasher,
    ) != Err(PasswdError::PolicyRejected)
        || !marker(b"PASSWD:POLICY_DENIED\n")
    {
        return false;
    }
    if engine
        .change_password(
            &mut database,
            alice,
            1000,
            Some(b"oldpass!"),
            b"newpass!",
            b"newpass!",
            &FixtureVerifier,
            &FixtureHasher,
        )
        .is_err()
        || !marker(b"PASSWD:CHANGE_OK\n")
    {
        return false;
    }
    if engine
        .change_password(
            &mut database,
            root,
            1000,
            None,
            b"resetpass!",
            b"resetpass!",
            &FixtureVerifier,
            &FixtureHasher,
        )
        .is_err()
        || !marker(b"PASSWD:RESET_OK\n")
    {
        return false;
    }
    if engine.set_locked(&mut database, alice, 1000, true) != Err(PasswdError::PermissionDenied)
        || !marker(b"PASSWD:LOCK_DENIED\n")
        || engine.set_locked(&mut database, root, 1000, true).is_err()
        || !marker(b"PASSWD:LOCK_OK\n")
        || engine.set_locked(&mut database, root, 1000, false).is_err()
        || !marker(b"PASSWD:UNLOCK_OK\n")
    {
        return false;
    }

    let mut storage = MemoryStorage::default();
    if storage.lock().is_err()
        || engine.commit(&mut storage, b"db", b"tmp", &database) != Err(PasswdError::StorageBusy)
        || !marker(b"PASSWD:CONCURRENT_DENIED\n")
        || storage.unlock().is_err()
        || engine
            .commit(&mut storage, b"db", b"tmp", &database)
            .is_err()
        || !marker(b"PASSWD:ATOMIC_OK\n")
    {
        return false;
    }
    storage.committed = Some(b"corrupt".to_vec());
    storage.temporary = Some(SEED.to_vec());
    if engine
        .recover(&mut storage, b"db", b"tmp")
        .map(|value| value.1)
        != Ok(RecoveryState::RecoveredTemp)
        || !marker(b"PASSWD:RECOVERED_OK\n")
    {
        return false;
    }
    storage.committed = Some(b"corrupt".to_vec());
    storage.temporary = Some(b"also corrupt".to_vec());
    if engine.recover(&mut storage, b"db", b"tmp") != Err(PasswdError::StorageCorrupt)
        || !marker(b"PASSWD:CORRUPT_FAIL_CLOSED\n")
    {
        return false;
    }
    if engine.audit().len() != 8 || !marker(b"PASSWD:AUDIT_REDACTED\n") {
        return false;
    }
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    syscall::exit(if run() { 0 } else { 1 })
}
