use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedSet;
use near_sdk::{env, near_bindgen, Promise, PromiseOrValue};

#[global_allocator]
static ALLOC: near_sdk::wee_alloc::WeeAlloc = near_sdk::wee_alloc::WeeAlloc::INIT;


pub type AccountId = String;
pub type PublicKey = Vec<u8>;
pub type Salt = u64;

/// A Faucet contract that creates and funds accounts if the caller provides basic proof of work
/// to avoid sybil attacks and draining balance too fast.
/// The new account always receives 1/1000 of the remaining balance.
/// Proof of Work works the following way:
/// You need to compute a u64 salt (nonce) for a given account and a given public key in such a way
/// that the `sha256(account_id + ':' + public_key + ':' + salt)` has more leading zero bits than
/// the required `min_difficulty`.
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Faucet {
    /// Account ID which will be a suffix for each account (including a '.' separator).
    pub account_suffix: AccountId,
    /// Number of leading zeros in binary representation for a hash
    pub min_difficulty: u32,
    /// Created accounts
    pub created_accounts: UnorderedSet<AccountId>,
}

impl Default for Faucet {
    fn default() -> Self {
        panic!("Faucet is not initialized yet")
    }
}

/// Returns the number of leading zero bits for a given slice of bits.
fn num_leading_zeros(v: &[u8]) -> u32 {
    let mut res = 0;
    for z in v.iter().map(|b| b.leading_zeros()) {
        res += z;
        if z < 8 {
            break;
        }
    }
    res
}

fn assert_self() {
    assert_eq!(
        env::current_account_id(),
        env::predecessor_account_id(),
        "Can only be called by owner"
    );
}

#[near_bindgen]
impl Faucet {
    #[init]
    pub fn new(account_suffix: AccountId, min_difficulty: u32) -> Self {
        assert!(env::state_read::<Self>().is_none(), "Already initialized");
        Self {
            account_suffix,
            min_difficulty,
            created_accounts: UnorderedSet::new(b"a".to_vec()),
        }
    }

    pub fn get_account_suffix(&self) -> AccountId {
        self.account_suffix.clone()
    }

    pub fn get_min_difficulty(&self) -> u32 {
        self.min_difficulty
    }

    pub fn get_num_created_accounts(&self) -> u64 {
        self.created_accounts.len()
    }

    pub fn create_account(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
        salt: Salt,
    ) -> PromiseOrValue<()> {
        // Checking account_id suffix first.
        assert!(
            account_id.ends_with(&self.account_suffix),
            "Account has to end with the suffix"
        );

        // Checking that the given account is not created yet.
        assert!(
            !self.created_accounts.contains(&account_id),
            "The given given account is already created"
        );

        // Checking proof of work
        //     Constructing a message for checking
        let mut message = account_id.as_bytes().to_vec();
        message.push(b':');
        message.extend_from_slice(&public_key);
        message.push(b':');
        message.extend_from_slice(&salt.to_le_bytes());
        //     Computing hash of the message
        let hash = env::sha256(&message);
        //     Checking that the resulting hash has enough leading zeros.
        assert!(
            num_leading_zeros(&hash) >= self.min_difficulty,
            "The proof is work is too weak"
        );

        // All checks are good, let's proceed by creating an account

        // Save that we already has created an account.
        self.created_accounts.insert(&account_id);

        // Creating new account. It still can fail (e.g. account already exists or name is invalid),
        // but we don't care, we'll get a refund back.
        Promise::new(account_id)
            .create_account()
            .transfer(env::account_balance() / 1000)
            .add_full_access_key(public_key)
            .into()
    }

    // Owner's methods. Can only be called by the owner

    pub fn set_min_difficulty(&mut self, min_difficulty: u32) {
        assert_self();
        self.min_difficulty = min_difficulty;
    }

    pub fn add_access_key(&mut self, public_key: PublicKey) -> PromiseOrValue<()> {
        assert_self();
        Promise::new(env::current_account_id())
            .add_access_key(
                public_key,
                0,
                env::current_account_id(),
                b"create_account".to_vec(),
            )
            .into()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};
    use std::panic;

    use super::*;

    fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(
        f: F,
    ) -> std::thread::Result<R> {
        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(f);
        panic::set_hook(prev_hook);
        result
    }

    fn get_context() -> VMContext {
        VMContext {
            current_account_id: "alice".to_string(),
            signer_account_id: "bob".to_string(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id: "bob".to_string(),
            input: vec![],
            block_index: 0,
            block_timestamp: 0,
            account_balance: 0,
            account_locked_balance: 0,
            storage_usage: 10u64.pow(6),
            attached_deposit: 0,
            prepaid_gas: 10u64.pow(15),
            random_seed: vec![0, 1, 2],
            is_view: false,
            output_data_receivers: vec![],
            epoch_height: 0,
        }
    }

    #[test]
    fn test_new() {
        let context = get_context();
        testing_env!(context);
        let account_suffix = ".alice".to_string();
        let min_difficulty = 5;
        let contract = Faucet::new(account_suffix.clone(), min_difficulty);
        assert_eq!(contract.get_account_suffix(), account_suffix);
        assert_eq!(contract.get_min_difficulty(), min_difficulty);
        assert_eq!(contract.get_num_created_accounts(), 0);
    }

    #[test]
    fn test_create_account_ok() {
        let context = get_context();
        testing_env!(context);
        let account_suffix = ".alice".to_string();
        let min_difficulty = 20;
        let mut contract = Faucet::new(account_suffix.clone(), min_difficulty);
        let account_id = "test.alice";
        let public_key = vec![0u8; 33];
        let salt = 89949;
        contract.create_account(account_id.to_string(), public_key, salt);
        assert_eq!(contract.get_num_created_accounts(), 1);
    }

    #[test]
    fn test_fail_default() {
        let context = get_context();
        testing_env!(context);
        catch_unwind_silent(|| {
            Faucet::default();
        })
        .unwrap_err();
    }

    #[test]
    fn test_fail_create_account_bad_name() {
        let context = get_context();
        testing_env!(context);
        let account_suffix = ".alice".to_string();
        let min_difficulty = 0;
        let mut contract = Faucet::new(account_suffix.clone(), min_difficulty);
        let account_id = "bob";
        let public_key = vec![0u8; 33];
        let salt = 0;
        catch_unwind_silent(move || {
            contract.create_account(account_id.to_string(), public_key, salt);
        })
        .unwrap_err();
    }

    #[test]
    fn test_fail_create_account_already_created() {
        let context = get_context();
        testing_env!(context);
        let account_suffix = ".alice".to_string();
        let min_difficulty = 10;
        let mut contract = Faucet::new(account_suffix.clone(), min_difficulty);
        let account_id = "test.alice";
        let public_key = vec![0u8; 33];
        let salt = 123;
        contract.create_account(account_id.to_string(), public_key.clone(), salt);
        catch_unwind_silent(move || {
            contract.create_account(account_id.to_string(), public_key, salt);
        })
        .unwrap_err();
    }

    #[test]
    fn test_num_leading_zeros() {
        assert_eq!(num_leading_zeros(&[0u8; 4]), 32);
        assert_eq!(num_leading_zeros(&[255u8; 4]), 0);
        assert_eq!(num_leading_zeros(&[254u8; 4]), 0);
        assert_eq!(num_leading_zeros(&[]), 0);
        assert_eq!(num_leading_zeros(&[127u8]), 1);
        assert_eq!(num_leading_zeros(&[0u8; 32]), 256);
        assert_eq!(num_leading_zeros(&[1u8; 4]), 7);
        assert_eq!(num_leading_zeros(&[0u8, 0u8, 255u8 >> 3]), 19);
        assert_eq!(num_leading_zeros(&[0u8, 0u8, 255u8 >> 3, 0u8]), 19);
    }
}
