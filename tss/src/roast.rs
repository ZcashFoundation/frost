use anyhow::Result;
use frost_evm::{
	keys::{KeyPackage, PublicKeyPackage},
	round1::{self, SigningCommitments, SigningNonces},
	round2::{self, SignatureShare},
	Identifier, Signature, SigningPackage, VerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RoastSignerRequest {
	session_id: u16,
	commitments: BTreeMap<Identifier, SigningCommitments>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct RoastSignerResponse {
	session_id: u16,
	signature_share: SignatureShare,
	commitment: SigningCommitments,
}

struct RoastSigner {
	key_package: KeyPackage,
	data: Vec<u8>,
	coordinators: BTreeMap<Identifier, SigningNonces>,
}

impl RoastSigner {
	pub fn new(key_package: KeyPackage, data: Vec<u8>) -> Self {
		Self {
			key_package,
			data,
			coordinators: Default::default(),
		}
	}

	pub fn data(&self) -> &[u8] {
		&self.data
	}

	pub fn commit(&mut self, coordinator: Identifier) -> SigningCommitments {
		let (nonces, commitment) = round1::commit(self.key_package.secret_share(), &mut OsRng);
		self.coordinators.insert(coordinator, nonces);
		commitment
	}

	pub fn sign(
		&mut self,
		coordinator: Identifier,
		request: RoastSignerRequest,
	) -> Result<RoastSignerResponse> {
		let session_id = request.session_id;
		let signing_package = SigningPackage::new(request.commitments, &self.data);
		let nonces = self
			.coordinators
			.remove(&coordinator)
			.expect("we sent the coordinator a commitment");
		let signature_share = round2::sign(&signing_package, &nonces, &self.key_package)?;
		let commitment = self.commit(coordinator);
		Ok(RoastSignerResponse {
			session_id,
			signature_share,
			commitment,
		})
	}
}

struct RoastSession {
	commitments: BTreeMap<Identifier, SigningCommitments>,
	signature_shares: HashMap<Identifier, SignatureShare>,
}

impl RoastSession {
	fn new(commitments: BTreeMap<Identifier, SigningCommitments>) -> Self {
		Self {
			commitments,
			signature_shares: Default::default(),
		}
	}

	fn on_signature_share(&mut self, peer: Identifier, signature_share: SignatureShare) {
		if self.commitments.contains_key(&peer) {
			self.signature_shares.insert(peer, signature_share);
		}
	}

	fn is_complete(&self) -> bool {
		self.commitments.len() == self.signature_shares.len()
	}
}

struct RoastCoordinator {
	threshold: u16,
	session_id: u16,
	commitments: BTreeMap<Identifier, SigningCommitments>,
	sessions: BTreeMap<u16, RoastSession>,
}

impl RoastCoordinator {
	fn new(threshold: u16) -> Self {
		Self {
			threshold,
			session_id: 0,
			commitments: Default::default(),
			sessions: Default::default(),
		}
	}

	fn on_commit(&mut self, peer: Identifier, commitment: SigningCommitments) {
		self.commitments.insert(peer, commitment);
	}

	fn on_response(&mut self, peer: Identifier, message: RoastSignerResponse) {
		if let Some(session) = self.sessions.get_mut(&message.session_id) {
			self.commitments.insert(peer, message.commitment);
			session.on_signature_share(peer, message.signature_share);
		}
	}

	fn start_session(&mut self) -> Option<RoastSignerRequest> {
		if self.commitments.len() < self.threshold as _ {
			log::debug!("commitments {}/{}", self.commitments.len(), self.threshold);
			return None;
		}
		let session_id = self.session_id;
		self.session_id += 1;
		let mut commitments = std::mem::take(&mut self.commitments);
		while commitments.len() > self.threshold as _ {
			let (peer, commitment) = commitments.pop_last().unwrap();
			self.commitments.insert(peer, commitment);
		}
		self.sessions.insert(session_id, RoastSession::new(commitments.clone()));
		Some(RoastSignerRequest { session_id, commitments })
	}

	fn aggregate_signature(&mut self) -> Option<RoastSession> {
		let session_id = self
			.sessions
			.iter()
			.filter(|(_, session)| session.is_complete())
			.map(|(session_id, _)| *session_id)
			.next()?;
		self.sessions.remove(&session_id)
	}
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum RoastRequest {
	Commit(SigningCommitments),
	Sign(RoastSignerRequest),
}

impl std::fmt::Display for RoastRequest {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::Commit(_) => write!(f, "commit"),
			Self::Sign(_) => write!(f, "sign"),
		}
	}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoastAction {
	Send(Identifier, RoastRequest),
	SendMany(Vec<Identifier>, RoastRequest),
	Complete([u8; 32], Signature),
}

/// ROAST state machine.
pub struct Roast {
	signer: RoastSigner,
	coordinator: Option<RoastCoordinator>,
	public_key_package: PublicKeyPackage,
	coordinators: BTreeSet<Identifier>,
}

impl Roast {
	pub fn new(
		id: Identifier,
		threshold: u16,
		key_package: KeyPackage,
		public_key_package: PublicKeyPackage,
		data: Vec<u8>,
		coordinators: BTreeSet<Identifier>,
	) -> Self {
		let is_coordinator = coordinators.contains(&id);
		Self {
			signer: RoastSigner::new(key_package, data),
			coordinator: if is_coordinator { Some(RoastCoordinator::new(threshold)) } else { None },
			public_key_package,
			coordinators,
		}
	}

	pub fn on_request(
		&mut self,
		peer: Identifier,
		request: RoastRequest,
	) -> Result<Option<RoastSignerResponse>> {
		match request {
			RoastRequest::Commit(commitment) => {
				if let Some(coordinator) = self.coordinator.as_mut() {
					coordinator.on_commit(peer, commitment);
					Ok(None)
				} else {
					anyhow::bail!("not coordinator");
				}
			},
			RoastRequest::Sign(request) => Ok(Some(self.signer.sign(peer, request)?)),
		}
	}

	pub fn on_response(&mut self, peer: Identifier, response: RoastSignerResponse) {
		if let Some(coordinator) = self.coordinator.as_mut() {
			coordinator.on_response(peer, response);
		}
	}

	pub fn next_action(&mut self) -> Option<RoastAction> {
		if let Some(coordinator) = self.coordinator.as_mut() {
			if let Some(session) = coordinator.aggregate_signature() {
				let signing_package = SigningPackage::new(session.commitments, self.signer.data());
				if let Ok(signature) = frost_evm::aggregate(
					&signing_package,
					&session.signature_shares,
					&self.public_key_package,
				) {
					let hash = VerifyingKey::message_hash(self.signer.data());
					return Some(RoastAction::Complete(hash, signature));
				}
			}
			if let Some(request) = coordinator.start_session() {
				let peers = request.commitments.keys().copied().collect();
				return Some(RoastAction::SendMany(peers, RoastRequest::Sign(request)));
			}
		}
		if let Some(coordinator) = self.coordinators.pop_last() {
			return Some(RoastAction::Send(
				coordinator,
				RoastRequest::Commit(self.signer.commit(coordinator)),
			));
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use anyhow::Result;
	use frost_evm::keys::{generate_with_dealer, IdentifierList};

	#[test]
	fn test_roast() -> Result<()> {
		env_logger::try_init().ok();
		let signers = 3;
		let threshold = 2;
		let coordinator = 1;
		let data = b"a message to sing".to_vec();
		let (secret_shares, public_key_package) =
			generate_with_dealer(signers, threshold, IdentifierList::Default, &mut OsRng).unwrap();
		let coordinators: BTreeSet<_> = secret_shares.keys().copied().take(coordinator).collect();
		let mut roasts: BTreeMap<_, _> = secret_shares
			.into_iter()
			.map(|(peer, secret_share)| {
				(
					peer,
					Roast::new(
						peer,
						threshold,
						KeyPackage::try_from(secret_share).unwrap(),
						public_key_package.clone(),
						data.clone(),
						coordinators.clone(),
					),
				)
			})
			.collect();
		let members: Vec<_> = roasts.keys().copied().collect();
		loop {
			for from in &members {
				if let Some(action) = roasts.get_mut(from).unwrap().next_action() {
					match action {
						RoastAction::Send(to, commitment) => {
							if let Some(response) =
								roasts.get_mut(&to).unwrap().on_request(*from, commitment)?
							{
								roasts.get_mut(from).unwrap().on_response(to, response);
							}
						},
						RoastAction::SendMany(peers, request) => {
							for to in peers {
								if let Some(response) = roasts
									.get_mut(&to)
									.unwrap()
									.on_request(*from, request.clone())?
								{
									roasts.get_mut(from).unwrap().on_response(to, response);
								}
							}
						},
						RoastAction::Complete(_hash, _signature) => {
							return Ok(());
						},
					}
				}
			}
		}
	}
}
