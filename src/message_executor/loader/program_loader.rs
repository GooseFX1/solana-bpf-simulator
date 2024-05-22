use std::sync::{atomic::Ordering, Arc};

use anyhow::Error;
use fehler::throws;
use solana_program_runtime::loaded_programs::{
    LoadProgramMetrics, LoadedProgram, LoadedProgramMatchCriteria, LoadedProgramType, LoadedProgramsForTxBatch, WorkingSlot, DELAY_VISIBILITY_SLOT_OFFSET
};
use solana_sdk::{
    account::{AccountSharedData, ReadableAccount},
    account_utils::StateMut,
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    epoch_schedule::DEFAULT_SLOTS_PER_EPOCH,
    feature_set,
    instruction::InstructionError,
    loader_v4::{self, LoaderV4State},
    message::SanitizedMessage,
    pubkey::Pubkey,
    slot_history::Slot,
    sysvar,
    transaction::TransactionError,
    transaction_context::TransactionContext,
};

use super::AccountLoader;

impl<'a, G> AccountLoader<'a, G>
where
    G: FnMut(&Pubkey) -> Option<AccountSharedData>,
{
    #[throws(Error)]
    pub fn replenish_program_cache<'b, I, S>(&mut self, s: &S, messages: I) -> LoadedProgramsForTxBatch
    where
        I: IntoIterator<Item = &'b SanitizedMessage>,
        S: WorkingSlot,
    {
        let mut missing_programs: Vec<(Pubkey, (LoadedProgramMatchCriteria, u64))> = vec![];
        for msg in messages {
            for &key in msg.account_keys().iter() {
                let acc = self
                    .get_account_with_fixed_root(&key)?
                    .ok_or(TransactionError::AccountNotFound)?;
                if self.program_owners.contains(&acc.owner()) {
                    if let Err(i) = missing_programs.binary_search_by_key(&key, |(key, _)| *key) {
                        missing_programs
                            .insert(i, (key, (LoadedProgramMatchCriteria::NoCriteria, 0)));
                    }
                }
            }
        }
        for builtin_program in self.builtin_programs.iter() {
            if let Err(i) = missing_programs.binary_search_by_key(builtin_program, |(key, _)| *key)
            {
                missing_programs.insert(
                    i,
                    (
                        *builtin_program,
                        (LoadedProgramMatchCriteria::NoCriteria, 0),
                    ),
                );
            }
        }

        let mut loaded_programs_for_txs = LoadedProgramsForTxBatch::new(s.current_slot());

        // Lock the global cache to figure out which programs need to be loaded
        self.loaded_programs_cache.extract(s, &mut missing_programs);

        let loaded_programs: Vec<(Pubkey, Arc<LoadedProgram>)> = missing_programs
            .iter()
            .map(|(key, (_match_criteria, count))| {
                let program = self.load_program(s.current_slot(), key)?;
                program.tx_usage_counter.store(*count, Ordering::Relaxed);
                Result::<_, Error>::Ok((*key, Arc::new(program)))
            })
            .collect::<Result<_, _>>()?;

        for (key, program) in loaded_programs {
            let (_, entry) = self.loaded_programs_cache.replenish(key, program);
            // Use the returned entry as that might have been deduplicated globally
            loaded_programs_for_txs.replenish(key, entry);
        }

        loaded_programs_for_txs
    }

    #[throws(Error)]
    fn load_program_accounts(&mut self, pubkey: &Pubkey) -> ProgramAccountLoadResult {
        let program_account = match self.get_account_with_fixed_root(pubkey)? {
            None => return ProgramAccountLoadResult::AccountNotFound,
            Some(account) => account,
        };

        if loader_v4::check_id(program_account.owner()) {
            return solana_loader_v4_program::get_state(program_account.data())
                .ok()
                .and_then(|state| {
                    (!matches!(state.status, LoaderV4Status::Retracted)).then_some(state.slot)
                })
                .map(|slot| ProgramAccountLoadResult::ProgramOfLoaderV4(program_account, slot))
                .unwrap_or(ProgramAccountLoadResult::InvalidV4Program);
        }

        if !bpf_loader_upgradeable::check_id(program_account.owner()) {
            return ProgramAccountLoadResult::ProgramOfLoaderV1orV2(program_account);
        }

        if let Ok(UpgradeableLoaderState::Program {
            programdata_address,
        }) = program_account.state()
        {
            let programdata_account =
                match self.get_account_with_fixed_root(&programdata_address)? {
                    None => return ProgramAccountLoadResult::AccountNotFound,
                    Some(account) => account,
                };

            if let Ok(UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority_address: _,
            }) = programdata_account.state()
            {
                return ProgramAccountLoadResult::ProgramOfLoaderV3(
                    program_account,
                    programdata_account,
                    slot,
                );
            }
        }
        ProgramAccountLoadResult::InvalidAccountData
    }

    // Roughly Bank::load_program
    #[throws(Error)]
    pub fn load_program(&mut self, slot: Slot, pubkey: &Pubkey) -> Arc<LoadedProgram> {
      let program = self
          .get_account_with_fixed_root(pubkey)?
          .ok_or(TransactionError::AccountNotFound)?;

      let mut transaction_accounts = vec![(*pubkey, program)];
      let is_upgradeable_loader =
          bpf_loader_upgradeable::check_id(transaction_accounts[0].1.owner());
      if is_upgradeable_loader {
          let programdata_address = match transaction_accounts[0].1.state() {
              Ok(UpgradeableLoaderState::Program {
                  programdata_address,
              }) => programdata_address,
              _ => {
                  return Arc::new(LoadedProgram::new_tombstone(
                      slot,
                      LoadedProgramType::Closed,
                  ));
              }
          };

          let programdata_account = self
              .get_account_with_fixed_root(&programdata_address)?
              .ok_or(TransactionError::AccountNotFound)?;

          transaction_accounts.push((programdata_address, programdata_account));
      }

      let mut transaction_context = TransactionContext::new(
          transaction_accounts,
          Some(sysvar::rent::Rent::default()),
          1,
          1,
      );
      let instruction_context = transaction_context.get_next_instruction_context().unwrap();
      instruction_context.configure(if is_upgradeable_loader { &[0, 1] } else { &[0] }, &[], &[]);
      transaction_context.push().unwrap();
      let instruction_context = transaction_context
          .get_current_instruction_context()
          .unwrap();
      let program = instruction_context
          .try_borrow_program_account(&transaction_context, 0)
          .unwrap();
      let programdata = if is_upgradeable_loader {
          Some(
              instruction_context
                  .try_borrow_program_account(&transaction_context, 1)
                  .unwrap(),
          )
      } else {
          None
      };
      solana_bpf_loader_program::load_program_from_account(
          &self.feature_set,
          None, // log_collector
          &program,
          programdata.as_ref().unwrap_or(&program),
          self.environment.clone(),
      )
      .map(|(loaded_program, _)| loaded_program)
      .unwrap_or_else(|_| {
          Arc::new(LoadedProgram::new_tombstone(
              slot,
              LoadedProgramType::FailedVerification(self.environment.clone()),
          ))
      })
  }
}

enum ProgramAccountLoadResult {
  AccountNotFound,
  InvalidAccountData,
  InvalidV4Program,
  ProgramOfLoaderV1orV2(AccountSharedData),
  ProgramOfLoaderV3(AccountSharedData, AccountSharedData, Slot),
  ProgramOfLoaderV4(AccountSharedData, Slot),
}
