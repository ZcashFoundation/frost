use crate::dkg::{Dkg, DkgAction, DkgMessage};
use crate::roast::{Roast, RoastAction, RoastRequest, RoastSignerResponse};
use crate::rts::{Rts, RtsAction, RtsHelper, RtsRequest, RtsResponse};
use anyhow::Result;
use frost_evm::keys::{
	KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
};
use frost_evm::{Identifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub mod dkg;
pub mod roast;
pub mod rts;
#[cfg(test)]
mod tests;

enum TssState<I> {
	Dkg(Dkg),
	Rts(Rts),
	Roast {
		rts: RtsHelper,
		key_package: KeyPackage,
		public_key_package: PublicKeyPackage,
		signing_sessions: BTreeMap<I, Roast>,
	},
}

#[derive(Clone)]
pub enum TssAction<I, P> {
	Send(Vec<(P, TssRequest<I>)>),
	Commit(VerifiableSecretSharingCommitment, frost_evm::frost_secp256k1::Signature),
	PublicKey(VerifyingKey),
	Signature(I, [u8; 32], Signature),
	Failure,
}

/// Tss message.
#[derive(Clone, Deserialize, Serialize)]
pub enum TssRequest<I> {
	Dkg { msg: DkgMessage },
	Rts { msg: RtsRequest },
	Roast { id: I, msg: RoastRequest },
}

impl<I: std::fmt::Display> std::fmt::Display for TssRequest<I> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::Dkg { msg } => write!(f, "dkg {}", msg),
			Self::Rts { msg } => write!(f, "rts {}", msg),
			Self::Roast { id, msg } => write!(f, "roast {} {}", id, msg),
		}
	}
}

#[derive(Clone, Deserialize, Serialize)]
pub enum TssResponse<I> {
	Rts { msg: RtsResponse },
	Roast { id: I, msg: RoastSignerResponse },
}

impl<I: std::fmt::Display> std::fmt::Display for TssResponse<I> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::Rts { msg } => write!(f, "rts {}", msg),
			Self::Roast { id, .. } => write!(f, "roast {}", id),
		}
	}
}

fn peer_to_frost(peer: impl std::fmt::Display) -> Identifier {
	Identifier::derive(peer.to_string().as_bytes()).expect("non zero")
}

/// Tss state machine.
pub struct Tss<I, P> {
	peer_id: P,
	frost_id: Identifier,
	frost_to_peer: BTreeMap<Identifier, P>,
	threshold: u16,
	coordinators: BTreeSet<Identifier>,
	state: TssState<I>,
}

impl<I, P> Tss<I, P>
where
	I: Clone + Ord + std::fmt::Display,
	P: Clone + Ord + std::fmt::Display,
{
	pub fn new(
		peer_id: P,
		members: BTreeSet<P>,
		threshold: u16,
		commitment: Option<VerifiableSecretSharingCommitment>,
	) -> Self {
		debug_assert!(members.contains(&peer_id));
		let frost_id = peer_to_frost(&peer_id);
		let frost_to_peer: BTreeMap<_, _> =
			members.into_iter().map(|peer| (peer_to_frost(&peer), peer)).collect();
		let members: BTreeSet<_> = frost_to_peer.keys().copied().collect();
		let coordinators: BTreeSet<_> =
			members.iter().copied().take(members.len() - threshold as usize + 1).collect();
		let is_coordinator = coordinators.contains(&frost_id);
		log::debug!(
			"{} initialize {}/{} coordinator = {}",
			peer_id,
			threshold,
			members.len(),
			is_coordinator
		);
		Self {
			peer_id,
			frost_id,
			frost_to_peer,
			threshold,
			coordinators,
			state: if let Some(commitment) = commitment {
				TssState::Rts(Rts::new(frost_id, members, threshold, commitment))
			} else {
				TssState::Dkg(Dkg::new(frost_id, members, threshold))
			},
		}
	}

	pub fn peer_id(&self) -> &P {
		&self.peer_id
	}

	fn frost_to_peer(&self, frost: &Identifier) -> P {
		self.frost_to_peer.get(frost).unwrap().clone()
	}

	pub fn total_nodes(&self) -> usize {
		self.frost_to_peer.len()
	}

	pub fn threshold(&self) -> usize {
		self.threshold as _
	}

	pub fn on_request(
		&mut self,
		peer_id: P,
		request: TssRequest<I>,
	) -> Result<Option<TssResponse<I>>> {
		log::debug!("{} on_request {} {}", self.peer_id, peer_id, request);
		if self.peer_id == peer_id {
			anyhow::bail!("{} received message from self", self.peer_id);
		}
		let frost_id = peer_to_frost(&peer_id);
		if !self.frost_to_peer.contains_key(&frost_id) {
			anyhow::bail!("{} received message unknown peer {}", self.peer_id, peer_id);
		}
		match (&mut self.state, request) {
			(TssState::Dkg(dkg), TssRequest::Dkg { msg }) => {
				dkg.on_message(frost_id, msg);
				Ok(None)
			},
			(TssState::Roast { rts, .. }, TssRequest::Rts { msg }) => {
				let msg = rts.on_request(frost_id, msg)?;
				Ok(Some(TssResponse::Rts { msg }))
			},
			(TssState::Roast { signing_sessions, .. }, TssRequest::Roast { id, msg }) => {
				if let Some(session) = signing_sessions.get_mut(&id) {
					if let Some(msg) = session.on_request(frost_id, msg)? {
						Ok(Some(TssResponse::Roast { id, msg }))
					} else {
						Ok(None)
					}
				} else {
					anyhow::bail!("invalid signing session");
				}
			},
			(_, msg) => {
				anyhow::bail!("unexpected request {}", msg);
			},
		}
	}

	pub fn on_response(&mut self, peer_id: P, response: Option<TssResponse<I>>) {
		let frost_id = peer_to_frost(&peer_id);
		match (&mut self.state, response) {
			(TssState::Dkg(_), _) => {},
			(TssState::Rts(rts), Some(TssResponse::Rts { msg })) => {
				rts.on_response(frost_id, Some(msg));
			},
			(TssState::Rts(rts), None) => {
				rts.on_response(frost_id, None);
			},
			(TssState::Roast { signing_sessions, .. }, Some(TssResponse::Roast { id, msg })) => {
				if let Some(session) = signing_sessions.get_mut(&id) {
					session.on_response(frost_id, msg);
				} else {
					log::error!("invalid signing session");
				}
			},
			(TssState::Roast { .. }, None) => {},
			(_, Some(msg)) => {
				log::error!("invalid state ({}, {}, {})", self.peer_id, peer_id, msg);
			},
		}
	}

	pub fn on_commit(&mut self, commitment: VerifiableSecretSharingCommitment) {
		log::debug!("{} commit", self.peer_id);
		match &mut self.state {
			TssState::Dkg(dkg) => dkg.on_commit(commitment),
			_ => log::error!("unexpected commit"),
		}
	}

	pub fn on_sign(&mut self, id: I, data: Vec<u8>) {
		log::debug!("{} sign {}", self.peer_id, id);
		match &mut self.state {
			TssState::Roast {
				key_package,
				public_key_package,
				signing_sessions,
				..
			} => {
				let roast = Roast::new(
					self.frost_id,
					self.threshold,
					key_package.clone(),
					public_key_package.clone(),
					data,
					self.coordinators.clone(),
				);
				signing_sessions.insert(id, roast);
			},
			_ => {
				log::error!("not ready to sign");
			},
		}
	}

	pub fn next_action(&mut self) -> Option<TssAction<I, P>> {
		match &mut self.state {
			TssState::Dkg(dkg) => {
				match dkg.next_action()? {
					DkgAction::Send(msgs) => {
						return Some(TssAction::Send(
							msgs.into_iter()
								.map(|(peer, msg)| {
									(self.frost_to_peer(&peer), TssRequest::Dkg { msg })
								})
								.collect(),
						));
					},
					DkgAction::Commit(commitment, proof_of_knowledge) => {
						return Some(TssAction::Commit(commitment, proof_of_knowledge));
					},
					DkgAction::Complete(key_package, public_key_package, commitment) => {
						let secret_share = SecretShare::new(
							self.frost_id,
							*key_package.secret_share(),
							commitment,
						);
						let public_key =
							VerifyingKey::new(public_key_package.group_public().to_element());
						let members = self.frost_to_peer.keys().copied().collect();
						let rts =
							RtsHelper::new(self.frost_id, members, self.threshold, secret_share);
						self.state = TssState::Roast {
							rts,
							key_package,
							public_key_package,
							signing_sessions: Default::default(),
						};
						return Some(TssAction::PublicKey(public_key));
					},
					DkgAction::Failure => return Some(TssAction::Failure),
				};
			},
			TssState::Rts(rts) => match rts.next_action()? {
				RtsAction::Send(msgs) => {
					return Some(TssAction::Send(
						msgs.into_iter()
							.map(|(peer, msg)| (self.frost_to_peer(&peer), TssRequest::Rts { msg }))
							.collect(),
					));
				},
				RtsAction::Complete(key_package, public_key_package, commitment) => {
					let secret_share =
						SecretShare::new(self.frost_id, *key_package.secret_share(), commitment);
					let public_key =
						VerifyingKey::new(public_key_package.group_public().to_element());
					let members = self.frost_to_peer.keys().copied().collect();
					let rts = RtsHelper::new(self.frost_id, members, self.threshold, secret_share);
					self.state = TssState::Roast {
						rts,
						key_package,
						public_key_package,
						signing_sessions: Default::default(),
					};
					return Some(TssAction::PublicKey(public_key));
				},
				RtsAction::Failure => return Some(TssAction::Failure),
			},
			TssState::Roast { signing_sessions, .. } => {
				let session_ids: Vec<_> = signing_sessions.keys().cloned().collect();
				for id in session_ids {
					let session = signing_sessions.get_mut(&id).unwrap();
					while let Some(action) = session.next_action() {
						let (peers, send_to_self, msg) = match action {
							RoastAction::Send(peer, msg) => {
								if peer == self.frost_id {
									(vec![], true, msg)
								} else {
									(vec![peer], false, msg)
								}
							},
							RoastAction::SendMany(all_peers, msg) => {
								let peers: Vec<_> = all_peers
									.iter()
									.filter(|peer| **peer != self.frost_id)
									.copied()
									.collect();
								let send_to_self = peers.len() != all_peers.len();
								(peers, send_to_self, msg)
							},
							RoastAction::Complete(hash, signature) => {
								signing_sessions.remove(&id);
								return Some(TssAction::Signature(id, hash, signature));
							},
						};
						if send_to_self {
							if let Some(response) = session
								.on_request(self.frost_id, msg.clone())
								.expect("something wrong")
							{
								session.on_response(self.frost_id, response);
							}
						}
						if !peers.is_empty() {
							return Some(TssAction::Send(
								peers
									.into_iter()
									.map(|peer| {
										(
											self.frost_to_peer(&peer),
											TssRequest::Roast {
												id: id.clone(),
												msg: msg.clone(),
											},
										)
									})
									.collect(),
							));
						}
					}
				}
			},
		}
		None
	}
}
