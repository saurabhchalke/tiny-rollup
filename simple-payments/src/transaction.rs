use crate::account::{AccountId, AccountPublicKey, AccountSecretKey};
use crate::ledger::{self, Amount};
use crate::signature::{
    schnorr::{self, Schnorr},
    SignatureScheme,
};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_std::rand::Rng;
use linked_hash_map::LinkedHashMap;

/// Transaction transferring some amount from one account to another.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// The account information of the sender.
    pub sender: AccountId,
    /// The account information of the recipient.
    pub recipient: AccountId,
    /// The amount being transferred from the sender to the receiver.
    pub amount: Amount,
    /// The spend authorization is a signature over the sender, the recipient,
    /// and the amount.
    pub signature: schnorr::Signature<EdwardsProjective>,
}

impl Transaction {
    /// Verify just the signature in the transaction.
    fn verify_signature(
        &self,
        pp: &schnorr::Parameters<EdwardsProjective>,
        pub_key: &AccountPublicKey,
    ) -> bool {
        // The authorized message consists of
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let mut message = self.sender.to_bytes_le();
        message.extend(self.recipient.to_bytes_le());
        message.extend(self.amount.to_bytes_le());
        Schnorr::verify(pp, pub_key, &message, &self.signature).unwrap()
    }

    /// Check that the transaction is valid for the given ledger state. This checks
    /// the following conditions:
    /// 1. Verify that the signature is valid with respect to the public key
    /// corresponding to `self.sender`.
    /// 2. Verify that the sender's account has sufficient balance to finance
    /// the transaction.
    /// 3. Verify that the recipient's account exists.
    pub fn validate(&self, parameters: &ledger::Parameters, state: &ledger::State) -> bool {
        // Lookup public key corresponding to sender ID
        if let Some(sender_acc_info) = state.id_to_account_info.get(&self.sender) {
            let mut result = true;
            // Check that the account_info exists in the Merkle tree.
            result &= {
                let path = state
                    .account_merkle_tree
                    .generate_proof(self.sender.0 as usize)
                    .expect("path should exist");
                path.verify(
                    &parameters.leaf_crh_params,
                    &parameters.two_to_one_crh_params,
                    &state.account_merkle_tree.root(),
                    &sender_acc_info.to_bytes_le(),
                )
                .unwrap()
            };
            // Verify the signature against the sender pubkey.
            result &= self.verify_signature(&parameters.sig_params, &sender_acc_info.public_key);
            // assert!(result, "signature verification failed");
            // Verify the amount is available in the sender account.
            result &= self.amount <= sender_acc_info.balance;
            // Verify that recipient account exists.
            result &= state.id_to_account_info.get(&self.recipient).is_some();
            result
        } else {
            false
        }
    }

    /// Create a (possibly invalid) transaction.
    pub fn create<R: Rng>(
        parameters: &ledger::Parameters,
        sender: AccountId,
        recipient: AccountId,
        amount: Amount,
        sender_sk: &AccountSecretKey,
        rng: &mut R,
    ) -> Self {
        // The authorized message consists of (SenderAccId || RecipientAccId || Amount)
        let mut message = sender.to_bytes_le();
        message.extend(recipient.to_bytes_le());
        message.extend(amount.to_bytes_le());
        let signature = Schnorr::sign(&parameters.sig_params, sender_sk, &message, rng).unwrap();
        Self {
            sender,
            recipient,
            amount,
            signature,
        }
    }

    // Create a map from account IDs to secret keys.
    pub fn create_account_id_to_secret_key_map(
        account_ids: &[AccountId],
        secret_keys: &[AccountSecretKey],
    ) -> LinkedHashMap<AccountId, AccountSecretKey> {
        assert_eq!(account_ids.len(), secret_keys.len());
        let mut account_id_to_secret_key: LinkedHashMap<AccountId, AccountSecretKey> = LinkedHashMap::new();
        for (account_id, secret_key) in account_ids.iter().zip(secret_keys.iter()) {
            account_id_to_secret_key.insert(account_id.clone(), secret_key.clone());
        }
        account_id_to_secret_key
    }

    // Compress the state transition by combining multiple transactions from the same sender and recipient.
    pub fn compress(
        parameters: &ledger::Parameters,
        transactions: &[Self],
        account_id_to_secret_key: &LinkedHashMap<AccountId, AccountSecretKey>,
    ) -> Vec<Self> {
        // Collect all transactions from the same sender and recipient.
        let mut transactions_by_sender_and_recipient: LinkedHashMap<(AccountId, AccountId), Vec<&Self>> =
            LinkedHashMap::new();
        for transaction in transactions {
            let sender_and_recipient = (transaction.sender, transaction.recipient);
            if transactions_by_sender_and_recipient.contains_key(&sender_and_recipient) {
                transactions_by_sender_and_recipient
                    .get_mut(&sender_and_recipient)
                    .unwrap()
                    .push(transaction);
            } else {
                transactions_by_sender_and_recipient
                    .insert(sender_and_recipient, vec![transaction]);
            }
        }

        // Create a new transaction for each sender and recipient pair.
        let mut compressed_transactions: Vec<Self> = Vec::new();
        for (sender_and_recipient, transactions) in transactions_by_sender_and_recipient {
            // Sum the amounts of all transactions.
            let mut amount = Amount(0);
            for transaction in transactions {
                amount.0 += transaction.amount.0;
            }

            // Generate a new transaction.
            let sender = sender_and_recipient.0;
            let recipient = sender_and_recipient.1;
            let sender_sk = account_id_to_secret_key.get(&sender).unwrap();
            let mut rng = ark_std::test_rng();
            let new_transaction =
                Self::create(parameters, sender, recipient, amount, sender_sk, &mut rng);

            // Add the new transaction to the list of compressed transactions.
            compressed_transactions.push(new_transaction);
        }

        compressed_transactions
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ledger::{Parameters, State};

    #[test]
    fn create_account_id_to_secret_key_map_test() {
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, _alice_pk, alice_sk) =
            state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's make an account for Bob.
        let (bob_id, _bob_pk, bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        let account_ids = vec![alice_id, bob_id];
        let secret_keys = vec![alice_sk, bob_sk];
        let account_id_to_secret_key =
            Transaction::create_account_id_to_secret_key_map(&account_ids, &secret_keys);
        assert_eq!(account_id_to_secret_key.len(), 2);
    }

    #[test]
    fn compress_test() {
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, _alice_pk, alice_sk) =
            state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's make an account for Bob.
        let (bob_id, _bob_pk, bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's make an account for Charlie.
        let (charlie_id, _charlie_pk, charlie_sk) =
            state.sample_keys_and_register(&pp, &mut rng).unwrap();

        let account_ids = vec![alice_id, bob_id, charlie_id];
        let secret_keys = vec![alice_sk.clone(), bob_sk.clone(), charlie_sk.clone()];
        let account_id_to_secret_key =
            Transaction::create_account_id_to_secret_key_map(&account_ids, &secret_keys);

        // Let's give alice some money.
        state
            .update_balance(alice_id, Amount(100))
            .expect("Alice's account should exist");
        // Let's give bob some money.
        state
            .update_balance(bob_id, Amount(100))
            .expect("Bob's account should exist");

        // Let's make some transactions.
        let mut transactions: Vec<Transaction> = Vec::new();
        // Alice sends 10 to Bob.
        transactions.push(Transaction::create(
            &pp,
            alice_id,
            bob_id,
            Amount(10),
            &alice_sk,
            &mut rng,
        ));
        // Alice sends 20 to Bob.
        transactions.push(Transaction::create(
            &pp,
            alice_id,
            bob_id,
            Amount(20),
            &alice_sk,
            &mut rng,
        ));
        // Alice sends 30 to Bob.
        transactions.push(Transaction::create(
            &pp,
            alice_id,
            bob_id,
            Amount(30),
            &alice_sk,
            &mut rng,
        ));
        // Bob sends 5 to Charlie.
        transactions.push(Transaction::create(
            &pp,
            bob_id,
            charlie_id,
            Amount(5),
            &bob_sk,
            &mut rng,
        ));
        // Bob sends 10 to Charlie.
        transactions.push(Transaction::create(
            &pp,
            bob_id,
            charlie_id,
            Amount(10),
            &bob_sk,
            &mut rng,
        ));
        // Bob sends 15 to Charlie.
        transactions.push(Transaction::create(
            &pp,
            bob_id,
            charlie_id,
            Amount(15),
            &bob_sk,
            &mut rng,
        ));

        // Let's compress the transactions.
        let compressed_transactions =
            Transaction::compress(&pp, &transactions, &account_id_to_secret_key);

        // Let's check that the compressed transactions are correct.
        assert_eq!(compressed_transactions.len(), 2);
        // Alice sends 60 to Bob.
        assert_eq!(compressed_transactions[0].sender, alice_id);
        assert_eq!(compressed_transactions[0].recipient, bob_id);
        assert_eq!(compressed_transactions[0].amount, Amount(60));
        // Bob sends 30 to Charlie.
        assert_eq!(compressed_transactions[1].sender, bob_id);
        assert_eq!(compressed_transactions[1].recipient, charlie_id);
        assert_eq!(compressed_transactions[1].amount, Amount(30));
    }
}

// Ideas to make exercises more interesting/complex:
// 1. Add fees
// 2. Add recipient confirmation requirement if tx amount is too large.
// 3. Add authority confirmation if tx amount is too large.
// 4. Create account if it doesn't exist.
// 5. Add idea for compressing state transitions with repeated senders and recipients.
