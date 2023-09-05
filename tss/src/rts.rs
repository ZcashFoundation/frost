use anyhow::Result;
use frost_evm::frost_secp256k1::Secp256K1Sha256;
use frost_evm::k256::elliptic_curve::PrimeField;
use frost_evm::keys::repairable;
use frost_evm::keys::{
	KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
};
use frost_evm::{Identifier, Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Deserialize, Serialize)]
pub enum RtsRequest {
	Delta { session_id: u32, helpers: BTreeSet<Identifier> },
	Sigma { session_id: u32, deltas: BTreeMap<Identifier, [u8; 32]> },
}

impl std::fmt::Display for RtsRequest {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::Delta { .. } => write!(f, "delta"),
			Self::Sigma { .. } => write!(f, "sigma"),
		}
	}
}

#[derive(Clone, Deserialize, Serialize)]
pub enum RtsResponse {
	// TODO: delta share probably needs to be encrypted/authenticated
	Delta { session_id: u32, deltas: BTreeMap<Identifier, [u8; 32]> },
	Sigma { session_id: u32, sigma: [u8; 32] },
}

impl std::fmt::Display for RtsResponse {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::Delta { .. } => write!(f, "delta"),
			Self::Sigma { .. } => write!(f, "sigma"),
		}
	}
}

pub struct RtsHelper {
	identifier: Identifier,
	members: BTreeSet<Identifier>,
	threshold: u16,
	secret_share: SecretShare,
	secret_deltas: BTreeMap<(Identifier, u32), Scalar>,
}

impl RtsHelper {
	pub fn new(
		identifier: Identifier,
		members: BTreeSet<Identifier>,
		threshold: u16,
		secret_share: SecretShare,
	) -> Self {
		debug_assert!(members.contains(&identifier));
		Self {
			identifier,
			members,
			threshold,
			secret_share,
			secret_deltas: Default::default(),
		}
	}

	pub fn on_request(&mut self, peer: Identifier, msg: RtsRequest) -> Result<RtsResponse> {
		match msg {
			RtsRequest::Delta { session_id, helpers } => {
				if !helpers.contains(&self.identifier)
					|| !helpers.is_subset(&self.members)
					|| helpers.len() != self.threshold as usize
				{
					anyhow::bail!("invalid helpers");
				}
				let mut deltas = repairable::repair_share_step_1::<Secp256K1Sha256, _>(
					&helpers.into_iter().collect::<Vec<_>>(),
					&self.secret_share,
					&mut OsRng,
					peer,
				)?;
				let secret_delta = deltas.remove(&self.identifier).unwrap();
				self.secret_deltas.insert((peer, session_id), secret_delta);
				let deltas =
					deltas.into_iter().map(|(id, delta)| (id, delta.to_bytes().into())).collect();
				Ok(RtsResponse::Delta { session_id, deltas })
			},
			RtsRequest::Sigma { session_id, deltas } => {
				if deltas.contains_key(&self.identifier) {
					anyhow::bail!("invalid deltas");
				}
				for id in deltas.keys() {
					if !self.members.contains(id) {
						anyhow::bail!("invalid deltas");
					}
				}
				let Some(secret_delta) = self.secret_deltas.remove(&(peer, session_id)) else {
					anyhow::bail!("invalid session");
				};
				let mut deltas = deltas
					.into_iter()
					.filter_map(|(_, delta)| Option::from(Scalar::from_repr(delta.into())))
					.collect::<Vec<_>>();
				if deltas.len() != self.threshold as usize - 1 {
					anyhow::bail!("invalid deltas");
				}
				deltas.push(secret_delta);
				let sigma = repairable::repair_share_step_2(&deltas);
				Ok(RtsResponse::Sigma {
					session_id,
					sigma: sigma.to_bytes().into(),
				})
			},
		}
	}
}

pub enum RtsAction {
	Send(Vec<(Identifier, RtsRequest)>),
	Complete(KeyPackage, PublicKeyPackage, VerifiableSecretSharingCommitment),
	Failure,
}

struct RtsSession {
	helpers: BTreeSet<Identifier>,
	deltas: BTreeMap<Identifier, BTreeMap<Identifier, Scalar>>,
	sigmas: BTreeMap<Identifier, Scalar>,
}

impl RtsSession {
	fn new(helpers: BTreeSet<Identifier>) -> Self {
		Self {
			helpers,
			deltas: Default::default(),
			sigmas: Default::default(),
		}
	}

	fn on_deltas(&mut self, peer: Identifier, deltas: BTreeMap<Identifier, [u8; 32]>) -> bool {
		if !self.helpers.contains(&peer) {
			return false;
		}
		let deltas: BTreeMap<_, _> = deltas
			.into_iter()
			.filter(|(to, _)| *to != peer && self.helpers.contains(to))
			.filter_map(|(to, delta)| Some((to, Option::from(Scalar::from_repr(delta.into()))?)))
			.collect();
		if deltas.len() != self.helpers.len() - 1 {
			return false;
		}
		self.deltas.insert(peer, deltas);
		true
	}

	fn on_sigma(&mut self, peer: Identifier, sigma: [u8; 32]) -> bool {
		if !self.helpers.contains(&peer) {
			return false;
		}
		let Some(sigma) = Option::from(Scalar::from_repr(sigma.into())) else {
			return false;
		};
		self.sigmas.insert(peer, sigma);
		true
	}

	fn deltas(
		&self,
	) -> Option<impl Iterator<Item = (&Identifier, BTreeMap<Identifier, [u8; 32]>)>> {
		if self.deltas.len() == self.helpers.len() {
			Some(self.helpers.iter().map(|to| {
				let deltas = self
					.deltas
					.iter()
					.filter_map(|(from, deltas)| {
						let delta = deltas.get(to)?.to_bytes().into();
						Some((*from, delta))
					})
					.collect();
				(to, deltas)
			}))
		} else {
			None
		}
	}

	fn sigmas(&self) -> Option<Vec<Scalar>> {
		if self.sigmas.len() == self.helpers.len() {
			Some(self.sigmas.values().copied().collect())
		} else {
			None
		}
	}
}

pub struct Rts {
	id: Identifier,
	members: BTreeSet<Identifier>,
	threshold: u16,
	commitment: VerifiableSecretSharingCommitment,
	public_key_package: PublicKeyPackage,
	unhelpful: BTreeSet<Identifier>,
	session_id: u32,
	session: Option<RtsSession>,
}

impl Rts {
	pub fn new(
		id: Identifier,
		members: BTreeSet<Identifier>,
		threshold: u16,
		commitment: VerifiableSecretSharingCommitment,
	) -> Self {
		let public_key_package = PublicKeyPackage::from_commitment(&members, &commitment);
		Self {
			id,
			members,
			threshold,
			commitment,
			public_key_package,
			unhelpful: Default::default(),
			session_id: 0,
			session: None,
		}
	}

	fn session(&mut self, session_id: u32) -> Option<&mut RtsSession> {
		if self.session_id != session_id {
			return None;
		}
		self.session.as_mut()
	}

	fn abort_session(&mut self, peer: Identifier) {
		log::info!("aborting session {}", self.session_id);
		self.unhelpful.insert(peer);
		self.session.take();
		self.session_id += 1;
	}

	pub fn on_response(&mut self, peer: Identifier, msg: Option<RtsResponse>) {
		match msg {
			Some(RtsResponse::Delta { session_id, deltas }) => {
				let Some(session) = self.session(session_id) else {
					return;
				};
				if !session.on_deltas(peer, deltas) {
					self.abort_session(peer);
				}
			},
			Some(RtsResponse::Sigma { session_id, sigma }) => {
				let Some(session) = self.session(session_id) else {
					return;
				};
				if !session.on_sigma(peer, sigma) {
					self.abort_session(peer);
				}
			},
			None => {
				self.abort_session(peer);
			},
		}
	}

	pub fn next_action(&mut self) -> Option<RtsAction> {
		loop {
			if let Some(session) = self.session.as_mut() {
				if let Some(sigmas) = session.sigmas() {
					let secret_share =
						repairable::repair_share_step_3(&sigmas, self.id, &self.commitment);
					// TODO: handle failure somehow. maybe try a different set of random peers?
					let Ok(key_package) = KeyPackage::try_from(secret_share) else {
						return Some(RtsAction::Failure);
					};
					return Some(RtsAction::Complete(
						key_package,
						self.public_key_package.clone(),
						self.commitment.clone(),
					));
				} else if let Some(deltas) = session.deltas() {
					return Some(RtsAction::Send(
						deltas
							.map(|(to, deltas)| {
								(
									*to,
									RtsRequest::Sigma {
										session_id: self.session_id,
										deltas,
									},
								)
							})
							.collect(),
					));
				} else {
					return None;
				}
			} else {
				let helpers: BTreeSet<_> = self
					.members
					.iter()
					.filter(|helper| **helper != self.id)
					.filter(|helper| !self.unhelpful.contains(helper))
					.take(self.threshold as _)
					.copied()
					.collect();
				if helpers.len() != self.threshold as usize {
					return Some(RtsAction::Failure);
				}
				let session_id = self.session_id;
				self.session = Some(RtsSession::new(helpers.clone()));
				return Some(RtsAction::Send(
					helpers
						.iter()
						.map(|helper| {
							(
								*helper,
								RtsRequest::Delta {
									session_id,
									helpers: helpers.clone(),
								},
							)
						})
						.collect(),
				));
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use frost_evm::keys::{generate_with_dealer, IdentifierList};

	#[test]
	fn test_rts() -> Result<()> {
		env_logger::try_init().ok();
		let signers = 3;
		let threshold = 2;
		let (secret_shares, public_key_package) =
			generate_with_dealer(signers, threshold, IdentifierList::Default, &mut OsRng).unwrap();
		let members: BTreeSet<_> = secret_shares.keys().copied().collect();
		let commitment = secret_shares.values().next().unwrap().commitment();
		let mut helpers: BTreeMap<_, _> = members
			.iter()
			.skip(1)
			.map(|peer| {
				(
					*peer,
					RtsHelper::new(
						*peer,
						members.clone(),
						threshold,
						secret_shares.get(peer).unwrap().clone(),
					),
				)
			})
			.collect();
		let id = *members.iter().next().unwrap();
		let secret_share = secret_shares.get(&id).unwrap().clone();
		let key_package = KeyPackage::try_from(secret_share).unwrap();
		let mut rts = Rts::new(id, members, threshold, commitment.clone());
		while let Some(action) = rts.next_action() {
			match action {
				RtsAction::Send(msgs) => {
					for (peer, msg) in msgs {
						let response = helpers.get_mut(&peer).unwrap().on_request(id, msg).unwrap();
						rts.on_response(peer, Some(response));
					}
				},
				RtsAction::Complete(
					recovered_key_package,
					recovered_public_key_package,
					recovered_commitment,
				) => {
					assert_eq!(key_package, recovered_key_package);
					assert_eq!(public_key_package, recovered_public_key_package);
					assert_eq!(commitment, &recovered_commitment);
					return Ok(());
				},
				RtsAction::Failure => break,
			}
		}
		unreachable!();
	}
}
