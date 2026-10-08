//! Kani model of stored administrator authorization and writes.
//! Soroban Host signature validation is a TRUSTED boundary. The actual Host
//! and deployed contract are not verified by this finite pure Rust model.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminStorage {
    pub admin: u8,
    pub policy: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostAuthorization {
    Missing,
    SignedBy(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminWriteError {
    Unauthorized,
}

/// Model stored_admin.require_auth(): authenticate the PREVIOUSLY stored
/// principal, not an address supplied as part of this update request.
pub fn require_stored_admin(
    current_admin: u8,
    host: HostAuthorization,
) -> Result<(), AdminWriteError> {
    match host {
        HostAuthorization::SignedBy(signer) if signer == current_admin => Ok(()),
        _ => Err(AdminWriteError::Unauthorized),
    }
}

/// Both protected storage writes occur only after successful host auth.
pub fn guarded_admin_update(
    storage: &mut AdminStorage,
    host: HostAuthorization,
    requested_admin: u8,
    requested_policy: u8,
) -> Result<(), AdminWriteError> {
    require_stored_admin(storage.admin, host)?;
    storage.admin = requested_admin;
    storage.policy = requested_policy;
    Ok(())
}

/// Deliberately VULNERABLE missing-require_auth variant for negative proof.
/// Never connect this demonstration function to a Soroban contract.
#[cfg(any(kani, test))]
pub fn unguarded_admin_update(
    storage: &mut AdminStorage,
    requested_admin: u8,
    requested_policy: u8,
) {
    storage.admin = requested_admin;
    storage.policy = requested_policy;
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// Unconstrained symbolic old admin, signatures, and new storage values.
    /// The full pre-state must remain unchanged when host auth is absent or
    /// the signature comes from a non-admin principal.
    #[kani::proof]
    fn only_stored_admin_may_write_admin_storage() {
        let before = AdminStorage { admin: kani::any(), policy: kani::any() };
        let present: bool = kani::any();
        let signer: u8 = kani::any();
        let requested_admin: u8 = kani::any();
        let requested_policy: u8 = kani::any();
        let host = if present {
            HostAuthorization::SignedBy(signer)
        } else {
            HostAuthorization::Missing
        };
        let authorized = present && signer == before.admin;
        let mut after = before;
        let outcome =
            guarded_admin_update(&mut after, host, requested_admin, requested_policy);

        if authorized {
            assert!(outcome.is_ok());
            assert_eq!(after.admin, requested_admin);
            assert_eq!(after.policy, requested_policy);
        } else {
            assert!(outcome.is_err());
            assert_eq!(after, before, "unauthorized invocation wrote admin storage");
        }
    }

    /// Non-vacuity: a valid signature must actually allow a nontrivial write.
    #[kani::proof]
    fn valid_admin_signature_can_change_storage() {
        let admin: u8 = kani::any();
        let next_admin: u8 = kani::any();
        let next_policy: u8 = kani::any();
        kani::assume(next_admin != admin);

        let mut storage = AdminStorage { admin, policy: kani::any() };
        let result = guarded_admin_update(
            &mut storage, HostAuthorization::SignedBy(admin),
            next_admin, next_policy,
        );
        assert!(result.is_ok());
        assert_eq!(storage.admin, next_admin);
        assert_eq!(storage.policy, next_policy);
    }

    /// Expected failing invariant: removal of require_auth lets a caller
    /// with NO credentials change the admin; Kani must find a counterexample.
    #[kani::proof]
    #[kani::should_panic]
    fn missing_require_auth_exposes_unauthorized_write() {
        let admin: u8 = kani::any();
        let next_admin: u8 = kani::any();
        kani::assume(next_admin != admin);
        let before = AdminStorage { admin, policy: 0 };
        let mut after = before;
        let _no_signature = HostAuthorization::Missing;
        unguarded_admin_update(&mut after, next_admin, 1);
        assert_eq!(after, before, "missing require_auth allowed state mutation");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_writes_and_authorized_rotation() {
        let initial = AdminStorage { admin: 7, policy: 2 };
        for auth in [HostAuthorization::Missing, HostAuthorization::SignedBy(9)] {
            let mut state = initial;
            assert_eq!(guarded_admin_update(&mut state, auth, 9, 5),
                       Err(AdminWriteError::Unauthorized));
            assert_eq!(state, initial);
        }
        let mut state = initial;
        assert_eq!(guarded_admin_update(&mut state, HostAuthorization::SignedBy(7), 9, 5), Ok(()));
        assert_eq!(state, AdminStorage { admin: 9, policy: 5 });
        assert_eq!(guarded_admin_update(&mut state, HostAuthorization::SignedBy(7), 4, 1),
                   Err(AdminWriteError::Unauthorized));
        assert_eq!(state, AdminStorage { admin: 9, policy: 5 });
    }

    #[test]
    fn deliberately_unguarded_variant_changes_state_without_auth() {
        let mut state = AdminStorage { admin: 7, policy: 2 };
        unguarded_admin_update(&mut state, 9, 5);
        assert_eq!(state, AdminStorage { admin: 9, policy: 5 });
    }
}
