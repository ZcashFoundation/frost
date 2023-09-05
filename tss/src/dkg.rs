use frost_evm::frost_secp256k1::Signature;
use frost_evm::keys::dkg::*;
use frost_evm::keys::{
	KeyPackage, PublicKeyPackage, SecretShare, SigningShare, VerifiableSecretSharingCommitment,
};
use frost_evm::{Identifier, Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone)]
pub enum DkgAction {
	Commit(VerifiableSecretSharingCommitment, Signature),
	Send(Vec<(Identifier, DkgMessage)>),
	Complete(KeyPackage, PublicKeyPackage, VerifiableSecretSharingCommitment),
	Failure,
}

/// Tss message.
#[derive(Clone, Deserialize, Serialize)]
pub struct DkgMessage(round2::Package);

impl std::fmt::Display for DkgMessage {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "dkg")
	}
}

/// Distributed key generation state machine.
pub struct Dkg {
	id: Identifier,
	members: BTreeSet<Identifier>,
	threshold: u16,
	secret_package: Option<round1::SecretPackage>,
	commitment: Option<VerifiableSecretSharingCommitment>,
	sent_round2_packages: bool,
	round2_packages: HashMap<Identifier, round2::Package>,
}

impl Dkg {
	pub fn new(id: Identifier, members: BTreeSet<Identifier>, threshold: u16) -> Self {
		debug_assert!(members.contains(&id));
		Self {
			id,
			members,
			threshold,
			secret_package: None,
			commitment: None,
			sent_round2_packages: false,
			round2_packages: Default::default(),
		}
	}

	pub fn on_commit(&mut self, commitment: VerifiableSecretSharingCommitment) {
		self.commitment = Some(commitment);
	}

	pub fn on_message(&mut self, peer: Identifier, msg: DkgMessage) {
		self.round2_packages.insert(peer, msg.0);
	}

	pub fn next_action(&mut self) -> Option<DkgAction> {
		let Some(secret_package) = self.secret_package.as_ref() else {
			let (secret_package, round1_package) = match part1(self.id, self.members.len() as _, self.threshold, OsRng) {
				Ok(result) => result,
				Err(error) => {
					log::error!("dkg failed with {:?}", error);
					return Some(DkgAction::Failure)
				}
			};
			self.secret_package = Some(secret_package);
			return Some(DkgAction::Commit(round1_package.commitment().clone(), *round1_package.proof_of_knowledge()));
		};
		let Some(commitment) = self.commitment.as_ref() else {
			return None;
		};
		if !self.sent_round2_packages {
			let mut msgs = Vec::with_capacity(self.members.len());
			for peer in &self.members {
				if *peer == self.id {
					continue;
				}
				let share = SigningShare::from_coefficients(secret_package.coefficients(), *peer);
				msgs.push((*peer, DkgMessage(round2::Package::new(share))));
			}
			self.sent_round2_packages = true;
			return Some(DkgAction::Send(msgs));
		}
		if self.round2_packages.len() != self.members.len() - 1 {
			return None;
		}
		let signing_share = self
			.round2_packages
			.values()
			.map(|package| package.secret_share().clone())
			.chain(std::iter::once(SigningShare::from_coefficients(
				secret_package.coefficients(),
				self.id,
			)))
			.fold(SigningShare::new(Scalar::ZERO), |acc, e| {
				SigningShare::new(acc.to_scalar() + e.to_scalar())
			});
		let secret_share = SecretShare::new(self.id, signing_share, commitment.clone());
		let key_package = match KeyPackage::try_from(secret_share) {
			Ok(key_package) => key_package,
			Err(error) => {
				log::error!("dkg failed with {:?}", error);
				return Some(DkgAction::Failure);
			},
		};
		let public_key_package = PublicKeyPackage::from_commitment(&self.members, &commitment);
		Some(DkgAction::Complete(key_package, public_key_package, commitment.clone()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use frost_evm::frost_core::frost::keys::dkg::verify_proof_of_knowledge;
	use frost_evm::frost_core::frost::keys::{compute_group_commitment, default_identifiers};

	#[test]
	fn test_dkg() {
		env_logger::try_init().ok();
		let members: BTreeSet<_> = default_identifiers(3).into_iter().collect();
		let threshold = 2;
		let mut dkgs: HashMap<_, _> = members
			.iter()
			.map(|id| (*id, Dkg::new(*id, members.clone(), threshold)))
			.collect();
		let mut commitments = Vec::with_capacity(members.len());
		loop {
			for from in &members {
				match dkgs.get_mut(from).unwrap().next_action() {
					Some(DkgAction::Commit(commitment, proof_of_knowledge)) => {
						verify_proof_of_knowledge(*from, &commitment, proof_of_knowledge).unwrap();
						commitments.push(commitment);
						if commitments.len() == members.len() {
							let commitment = compute_group_commitment(&commitments);
							for dkg in dkgs.values_mut() {
								dkg.on_commit(commitment.clone());
							}
						}
					},
					Some(DkgAction::Send(msgs)) => {
						for (to, msg) in msgs {
							dkgs.get_mut(&to).unwrap().on_message(*from, msg);
						}
					},
					Some(DkgAction::Complete(_key_package, _public_key_package, _commitment)) => {
						return;
					},
					Some(DkgAction::Failure) => unreachable!(),
					None => {},
				}
			}
		}
	}
}
