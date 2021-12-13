use crate::{
    frost,
    messages::{
        validate::{MsgErr, Validate},
        *,
    },
    verification_key,
};
use rand::thread_rng;
use serde_json;
use std::convert::TryFrom;

#[test]
fn validate_version() {
    // A version number that we expect to be always invalid
    const INVALID_VERSION: u8 = u8::MAX;

    let setup = basic_setup();

    let header = Header {
        version: MsgVersion(INVALID_VERSION),
        sender: setup.dealer,
        receiver: setup.signer1,
    };

    let validate = Validate::validate(&header);
    assert_eq!(validate, Err(MsgErr::WrongVersion));

    let validate = Validate::validate(&Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: setup.dealer,
        receiver: setup.signer1,
    })
    .err();

    assert_eq!(validate, None);
}

#[test]
fn validate_sender_receiver() {
    let setup = basic_setup();

    let header = Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: setup.signer1,
        receiver: setup.signer1,
    };

    let validate = Validate::validate(&header);
    assert_eq!(validate, Err(MsgErr::SameSenderAndReceiver));
}

#[test]
fn validate_sharepackage() {
    let setup = basic_setup();
    let (mut shares, _pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    let header = create_valid_header(setup.signer1, setup.signer2);

    let group_public = VerificationKey::from(
        verification_key::VerificationKey::try_from(shares[0].group_public.bytes).unwrap(),
    );
    let secret_share = Secret(shares[0].share.value.0.to_bytes());

    let participants = vec![setup.signer1, setup.signer2];
    shares.truncate(2);
    let share_commitment = generate_share_commitment(&shares, participants);

    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share: secret_share,
        share_commitment: share_commitment,
    });
    let validate_payload = Validate::validate(&payload);
    let valid_payload = validate_payload.expect("a valid payload").clone();

    let message = Message {
        header,
        payload: valid_payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeDealer));

    // change the header
    let header = create_valid_header(setup.dealer, setup.aggregator);

    let message = Message {
        header,
        payload: valid_payload,
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeSigner));

    let participants = vec![setup.signer1];
    shares.truncate(1);
    let mut share_commitment = generate_share_commitment(&shares, participants);

    // change the payload to have only 1 commitment
    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share: secret_share,
        share_commitment: share_commitment.clone(),
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(
        validate_payload,
        Err(MsgErr::NotEnoughCommitments(constants::MIN_SIGNERS))
    );

    // build and use too many commitments
    for i in 2..constants::MAX_SIGNERS as u64 + 2 {
        share_commitment.insert(
            ParticipantId::Signer(i),
            share_commitment.clone()[&setup.signer1],
        );
    }
    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment,
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(validate_payload, Err(MsgErr::TooManyCommitments));
}

#[test]
fn serialize_sharepackage() {
    let setup = basic_setup();

    let (mut shares, _pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    let header = create_valid_header(setup.dealer, setup.signer1);

    let group_public = VerificationKey::from(
        verification_key::VerificationKey::try_from(shares[0].group_public.bytes).unwrap(),
    );
    let secret_share = Secret(shares[0].share.value.0.to_bytes());

    let participants = vec![setup.signer1];
    shares.truncate(1);
    let share_commitment = generate_share_commitment(&shares, participants);

    let payload = Payload::SharePackage(SharePackage {
        group_public,
        secret_share,
        share_commitment: share_commitment.clone(),
    });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    // check general structure and header serialization/deserialization
    serialize_message(message, setup.dealer, setup.signer1);

    // check payload serialization/deserialization
    let mut payload_serialized_bytes = bincode::serialize(&payload).unwrap();
    // check the message type is correct
    let deserialized_msg_type: MsgType =
        bincode::deserialize(&payload_serialized_bytes[0..4]).unwrap();
    assert_eq!(deserialized_msg_type, MsgType::SharePackage);

    // remove the msg_type from the the payload
    payload_serialized_bytes =
        (&payload_serialized_bytes[4..payload_serialized_bytes.len()]).to_vec();

    // group_public is 32 bytes
    let deserialized_group_public: VerificationKey =
        bincode::deserialize(&payload_serialized_bytes[0..32]).unwrap();
    // secret share is 32 bytes
    let deserialized_secret_share: Secret =
        bincode::deserialize(&payload_serialized_bytes[32..64]).unwrap();
    // rest of the message is the map: 32(Commitment) + 8(ParticipantId) + 8(map.len())
    let deserialized_share_commitment: BTreeMap<ParticipantId, Commitment> =
        bincode::deserialize(&payload_serialized_bytes[64..112]).unwrap();

    // check the map len
    let deserialized_map_len: u64 =
        bincode::deserialize(&payload_serialized_bytes[64..72]).unwrap();
    assert_eq!(deserialized_map_len, 1);

    // no leftover bytes
    assert_eq!(payload_serialized_bytes.len(), 112);

    assert_eq!(deserialized_group_public, group_public);
    assert_eq!(deserialized_secret_share, secret_share);
    assert_eq!(deserialized_share_commitment, share_commitment);
}

#[test]
fn validate_signingcommitments() {
    let mut setup = basic_setup();

    let (_nonce, commitment) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);

    let header = create_valid_header(setup.aggregator, setup.signer2);

    let payload = Payload::SigningCommitments(SigningCommitments {
        hiding: Commitment(jubjub::AffinePoint::from(commitment[0].hiding).to_bytes()),
        binding: Commitment(jubjub::AffinePoint::from(commitment[0].binding).to_bytes()),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeSigner));

    // change the header
    let header = create_valid_header(setup.signer1, setup.signer2);

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeAggregator));

    // change the header to be valid
    let header = create_valid_header(setup.signer1, setup.aggregator);

    let validate_message = Validate::validate(&Message { header, payload }).err();

    assert_eq!(validate_message, None);
}

#[test]
fn serialize_signingcommitments() {
    let mut setup = basic_setup();

    let (_nonce, commitment) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);

    let header = create_valid_header(setup.aggregator, setup.signer1);

    let hiding = Commitment(jubjub::AffinePoint::from(commitment[0].hiding).to_bytes());
    let binding = Commitment(jubjub::AffinePoint::from(commitment[0].binding).to_bytes());

    let payload = Payload::SigningCommitments(SigningCommitments { hiding, binding });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    // check general structure serialization/deserialization
    serialize_message(message, setup.aggregator, setup.signer1);

    // check payload serialization/deserialization
    let mut payload_serialized_bytes = bincode::serialize(&payload).unwrap();
    // check the message type is correct
    let deserialized_msg_type: MsgType =
        bincode::deserialize(&payload_serialized_bytes[0..4]).unwrap();
    assert_eq!(deserialized_msg_type, MsgType::SigningCommitments);

    // remove the msg_type from the the payload
    payload_serialized_bytes =
        (&payload_serialized_bytes[4..payload_serialized_bytes.len()]).to_vec();

    // hiding is 32 bytes
    let deserialized_hiding: Commitment =
        bincode::deserialize(&payload_serialized_bytes[0..32]).unwrap();
    // binding is 43 bytes kore
    let deserialized_binding: Commitment =
        bincode::deserialize(&payload_serialized_bytes[32..64]).unwrap();

    // no leftover bytes
    assert_eq!(payload_serialized_bytes.len(), 64);

    assert_eq!(deserialized_hiding, hiding);
    assert_eq!(deserialized_binding, binding);
}

#[test]
fn validate_signingpackage() {
    let mut setup = basic_setup();

    let (_nonce, commitment1) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);
    let (_nonce, commitment2) = frost::preprocess(1, u64::from(setup.signer2), &mut setup.rng);

    let header = create_valid_header(setup.signer1, setup.signer2);

    // try with only 1 commitment
    let commitments = vec![commitment1[0]];
    let participants = vec![setup.signer1];
    let signing_commitments = create_signing_commitments(commitments, participants);

    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(
        validate_payload,
        Err(MsgErr::NotEnoughCommitments(constants::MIN_SIGNERS))
    );

    // add too many commitments
    let mut big_signing_commitments = BTreeMap::<ParticipantId, SigningCommitments>::new();
    for i in 0..constants::MAX_SIGNERS as u64 + 1 {
        big_signing_commitments.insert(
            ParticipantId::Signer(i),
            signing_commitments[&setup.signer1].clone(),
        );
    }
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: big_signing_commitments,
        message: "hola".as_bytes().to_vec(),
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(validate_payload, Err(MsgErr::TooManyCommitments));

    // change to 2 commitments
    let commitments = vec![commitment1[0], commitment2[0]];
    let participants = vec![setup.signer1, setup.signer2];
    let signing_commitments = create_signing_commitments(commitments, participants);

    let big_message = [0u8; constants::ZCASH_MAX_PROTOCOL_MESSAGE_LEN + 1].to_vec();
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: big_message,
    });
    let validate_payload = Validate::validate(&payload);
    assert_eq!(validate_payload, Err(MsgErr::MsgTooBig));

    let message = Message {
        header,
        payload: payload.clone(),
    };
    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeAggregator));

    // change header
    let header = create_valid_header(setup.aggregator, setup.dealer);

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeSigner));

    let header = create_valid_header(setup.aggregator, setup.signer1);
    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments,
        message: "hola".as_bytes().to_vec(),
    });

    let validate_message = Validate::validate(&Message { header, payload }).err();
    assert_eq!(validate_message, None);
}

#[test]
fn serialize_signingpackage() {
    let mut setup = basic_setup();

    let (_nonce, commitment1) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);
    let (_nonce, commitment2) = frost::preprocess(1, u64::from(setup.signer2), &mut setup.rng);

    let header = create_valid_header(setup.aggregator, setup.signer1);

    let commitments = vec![commitment1[0], commitment2[0]];
    let participants = vec![setup.signer1, setup.signer2];
    let signing_commitments = create_signing_commitments(commitments, participants);

    let payload = Payload::SigningPackage(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    // check general structure serialization/deserialization
    serialize_message(message, setup.aggregator, setup.signer1);

    // check payload serialization/deserialization
    let mut payload_serialized_bytes = bincode::serialize(&payload).unwrap();

    // check the message type is correct
    let deserialized_msg_type: MsgType =
        bincode::deserialize(&payload_serialized_bytes[0..4]).unwrap();
    assert_eq!(deserialized_msg_type, MsgType::SigningPackage);

    // remove the msg_type from the the payload
    payload_serialized_bytes =
        (&payload_serialized_bytes[4..payload_serialized_bytes.len()]).to_vec();

    // check the map len
    let deserialized_map_len: u64 = bincode::deserialize(&payload_serialized_bytes[0..8]).unwrap();
    assert_eq!(deserialized_map_len, 2);

    // Each SigningCommitment is 64 bytes and the ParticipantId is 8 bytes.
    // This is multiplied by the map len, also include the map len bytes.
    let deserialized_signing_commitments: BTreeMap<ParticipantId, SigningCommitments> =
        bincode::deserialize(&payload_serialized_bytes[0..152]).unwrap();

    // Message is from the end of the map up to the end of the message.
    let deserialized_message: Vec<u8> =
        bincode::deserialize(&payload_serialized_bytes[152..payload_serialized_bytes.len()])
            .unwrap();

    // no leftover bytes
    assert_eq!(payload_serialized_bytes.len(), 164);

    assert_eq!(deserialized_signing_commitments, signing_commitments);
    assert_eq!(deserialized_message, "hola".as_bytes().to_vec());
}

#[test]
fn validate_signatureshare() {
    let mut setup = basic_setup();

    // signers and aggregator should have this data from `SharePackage`
    let (shares, _pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    // create a signing package, this is done in the aggregator side.
    // the signrs should have this data from `SigningPackage`
    let (nonce1, commitment1) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);
    let (_nonce2, commitment2) = frost::preprocess(1, u64::from(setup.signer2), &mut setup.rng);
    let commitments = vec![commitment1[0], commitment2[0]];
    let participants = vec![setup.signer1, setup.signer2];
    let signing_commitments = create_signing_commitments(commitments, participants);

    let signing_package = frost::SigningPackage::from(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });

    // here we get started with the `SignatureShare` message.
    let signature_share = frost::sign(&signing_package, nonce1[0], &shares[0]).unwrap();

    // this header is invalid
    let header = create_valid_header(setup.aggregator, setup.signer1);

    let payload = Payload::SignatureShare(SignatureShare {
        signature: SignatureResponse(signature_share.signature.0.to_bytes()),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeSigner));

    // change the header, still invalid.
    let header = create_valid_header(setup.signer1, setup.signer2);

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeAggregator));

    // change the header to be valid
    let header = create_valid_header(setup.signer1, setup.aggregator);

    let validate_message = Validate::validate(&Message { header, payload }).err();

    assert_eq!(validate_message, None);
}

#[test]
fn serialize_signatureshare() {
    let mut setup = basic_setup();

    // signers and aggregator should have this data from `SharePackage`
    let (shares, _pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    // create a signing package, this is done in the aggregator side.
    // the signers should have this data from `SigningPackage`
    let (nonce1, commitment1) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);
    let (_nonce2, commitment2) = frost::preprocess(1, u64::from(setup.signer2), &mut setup.rng);
    let commitments = vec![commitment1[0], commitment2[0]];
    let participants = vec![setup.signer1, setup.signer2];
    let signing_commitments = create_signing_commitments(commitments, participants);

    let signing_package = frost::SigningPackage::from(SigningPackage {
        signing_commitments: signing_commitments.clone(),
        message: "hola".as_bytes().to_vec(),
    });

    // here we get started with the `SignatureShare` message.
    let signature_share = frost::sign(&signing_package, nonce1[0], &shares[0]).unwrap();

    // valid header
    let header = create_valid_header(setup.signer1, setup.aggregator);

    let signature = SignatureResponse(signature_share.signature.0.to_bytes());
    let payload = Payload::SignatureShare(SignatureShare { signature });

    let message = Message {
        header: header,
        payload: payload.clone(),
    };

    // check general structure serialization/deserialization
    serialize_message(message, setup.signer1, setup.aggregator);

    // check payload serialization/deserialization
    let mut payload_serialized_bytes = bincode::serialize(&payload).unwrap();

    // check the message type is correct
    let deserialized_msg_type: MsgType =
        bincode::deserialize(&payload_serialized_bytes[0..4]).unwrap();
    assert_eq!(deserialized_msg_type, MsgType::SignatureShare);

    // remove the msg_type from the the payload
    payload_serialized_bytes =
        (&payload_serialized_bytes[4..payload_serialized_bytes.len()]).to_vec();

    // signature is 32 bytes
    let deserialized_signature: SignatureResponse =
        bincode::deserialize(&payload_serialized_bytes[0..32]).unwrap();

    // no leftover bytes
    assert_eq!(payload_serialized_bytes.len(), 32);

    assert_eq!(deserialized_signature, signature);
}

#[test]
fn validate_aggregatesignature() {
    let (setup, group_signature_res) = full_setup();

    // this header is invalid
    let header = create_valid_header(setup.signer1, setup.aggregator);

    let payload = Payload::AggregateSignature(AggregateSignature {
        group_commitment: GroupCommitment::from(group_signature_res),
        schnorr_signature: SignatureResponse::from(group_signature_res),
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::SenderMustBeAggregator));

    // change the header, still invalid.
    let header = create_valid_header(setup.aggregator, setup.dealer);

    let message = Message {
        header,
        payload: payload.clone(),
    };

    let validate_message = Validate::validate(&message);
    assert_eq!(validate_message, Err(MsgErr::ReceiverMustBeSigner));

    // change the header to be valid
    let header = create_valid_header(setup.aggregator, setup.signer1);

    let validate_message = Validate::validate(&Message { header, payload }).err();

    assert_eq!(validate_message, None);
}

#[test]
fn serialize_aggregatesignature() {
    let (setup, group_signature_res) = full_setup();

    let header = create_valid_header(setup.aggregator, setup.signer1);

    let group_commitment = GroupCommitment::from(group_signature_res);
    let schnorr_signature = SignatureResponse::from(group_signature_res);
    let payload = Payload::AggregateSignature(AggregateSignature {
        group_commitment,
        schnorr_signature,
    });

    let message = Message {
        header,
        payload: payload.clone(),
    };

    // check general structure serialization/deserialization
    serialize_message(message, setup.aggregator, setup.signer1);

    // check payload serialization/deserialization
    let mut payload_serialized_bytes = bincode::serialize(&payload).unwrap();

    // check the message type is correct
    let deserialized_msg_type: MsgType =
        bincode::deserialize(&payload_serialized_bytes[0..4]).unwrap();
    assert_eq!(deserialized_msg_type, MsgType::AggregateSignature);

    // remove the msg_type from the the payload
    payload_serialized_bytes =
        (&payload_serialized_bytes[4..payload_serialized_bytes.len()]).to_vec();

    // group_commitment is 32 bytes
    let deserialized_group_commiment: GroupCommitment =
        bincode::deserialize(&payload_serialized_bytes[0..32]).unwrap();
    // schnorr_signature is 32 bytes
    let deserialized_schnorr_signature: SignatureResponse =
        bincode::deserialize(&payload_serialized_bytes[32..64]).unwrap();

    // no leftover bytes
    assert_eq!(payload_serialized_bytes.len(), 64);

    assert_eq!(deserialized_group_commiment, group_commitment);
    assert_eq!(deserialized_schnorr_signature, schnorr_signature);
}

#[test]
fn btreemap() {
    let mut setup = basic_setup();
    let mut map = BTreeMap::new();

    let (_nonce, commitment) = frost::preprocess(1, u64::from(setup.signer1), &mut setup.rng);

    let commitments = vec![commitment[0]];
    let participants = vec![setup.signer1];
    let signing_commitments = create_signing_commitments(commitments, participants);

    map.insert(ParticipantId::Signer(1), &signing_commitments);
    map.insert(ParticipantId::Signer(2), &signing_commitments);
    map.insert(ParticipantId::Signer(0), &signing_commitments);

    // Check the ascending order
    let mut map_iter = map.iter();
    let (key, _) = map_iter.next().unwrap();
    assert_eq!(*key, ParticipantId::Signer(0));
    let (key, _) = map_iter.next().unwrap();
    assert_eq!(*key, ParticipantId::Signer(1));
    let (key, _) = map_iter.next().unwrap();
    assert_eq!(*key, ParticipantId::Signer(2));

    // Add a repeated key
    map.insert(ParticipantId::Signer(1), &signing_commitments);
    // BTreeMap is not increasing
    assert_eq!(map.len(), 3);
}

// utility functions

fn create_valid_header(sender: ParticipantId, receiver: ParticipantId) -> Header {
    Validate::validate(&Header {
        version: constants::BASIC_FROST_SERIALIZATION,
        sender: sender,
        receiver: receiver,
    })
    .expect("always a valid header")
    .clone()
}

fn serialize_header(
    header_serialized_bytes: Vec<u8>,
    sender: ParticipantId,
    receiver: ParticipantId,
) {
    let deserialized_version: MsgVersion =
        bincode::deserialize(&header_serialized_bytes[0..1]).unwrap();
    let deserialized_sender: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[1..9]).unwrap();
    let deserialized_receiver: ParticipantId =
        bincode::deserialize(&header_serialized_bytes[9..17]).unwrap();
    assert_eq!(deserialized_version, constants::BASIC_FROST_SERIALIZATION);
    assert_eq!(deserialized_sender, sender);
    assert_eq!(deserialized_receiver, receiver);
}

fn serialize_message(message: Message, sender: ParticipantId, receiver: ParticipantId) {
    let serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_bytes: Message = bincode::deserialize(&serialized_bytes).unwrap();
    assert_eq!(message, deserialized_bytes);

    let serialized_json = serde_json::to_string(&message).unwrap();
    let deserialized_json: Message = serde_json::from_str(serialized_json.as_str()).unwrap();
    assert_eq!(message, deserialized_json);

    let header_serialized_bytes = bincode::serialize(&message.header).unwrap();
    serialize_header(header_serialized_bytes, sender, receiver);

    // make sure the message fields are in the right order
    let message_serialized_bytes = bincode::serialize(&message).unwrap();
    let deserialized_header: Header =
        bincode::deserialize(&message_serialized_bytes[0..17]).unwrap();
    let deserialized_payload: Payload =
        bincode::deserialize(&message_serialized_bytes[17..message_serialized_bytes.len()])
            .unwrap();
    assert_eq!(deserialized_header, message.header);
    assert_eq!(deserialized_payload, message.payload);
}

struct Setup {
    rng: rand::rngs::ThreadRng,
    num_signers: u8,
    threshold: u8,
    dealer: ParticipantId,
    aggregator: ParticipantId,
    signer1: ParticipantId,
    signer2: ParticipantId,
}

fn basic_setup() -> Setup {
    Setup {
        rng: thread_rng(),
        num_signers: 3,
        threshold: 2,
        dealer: ParticipantId::Dealer,
        aggregator: ParticipantId::Aggregator,
        signer1: ParticipantId::Signer(0),
        signer2: ParticipantId::Signer(1),
    }
}

fn full_setup() -> (Setup, signature::Signature<SpendAuth>) {
    let mut setup = basic_setup();

    // aggregator creates the shares and pubkeys for this round
    let (shares, pubkeys) =
        frost::keygen_with_dealer(setup.num_signers, setup.threshold, setup.rng.clone()).unwrap();

    let mut nonces: std::collections::HashMap<u64, Vec<frost::SigningNonces>> =
        std::collections::HashMap::with_capacity(setup.threshold as usize);
    let mut commitments: Vec<frost::SigningCommitments> =
        Vec::with_capacity(setup.threshold as usize);

    // aggregator generates nonces and signing commitments for each participant.
    for participant_index in 1..(setup.threshold + 1) {
        let (nonce, commitment) = frost::preprocess(1, participant_index as u64, &mut setup.rng);
        nonces.insert(participant_index as u64, nonce);
        commitments.push(commitment[0]);
    }

    // aggregator generates a signing package
    let mut signature_shares: Vec<frost::SignatureShare> =
        Vec::with_capacity(setup.threshold as usize);
    let message = "message to sign".as_bytes().to_vec();
    let signing_package = frost::SigningPackage {
        message: message.clone(),
        signing_commitments: commitments,
    };

    // each participant generates their signature share
    for (participant_index, nonce) in nonces {
        let share_package = shares
            .iter()
            .find(|share| participant_index == share.index)
            .unwrap();
        let nonce_to_use = nonce[0];
        let signature_share = frost::sign(&signing_package, nonce_to_use, share_package).unwrap();
        signature_shares.push(signature_share);
    }

    // aggregator generate the final signature
    let final_signature =
        frost::aggregate(&signing_package, &signature_shares[..], &pubkeys).unwrap();
    (setup, final_signature)
}

fn generate_share_commitment(
    shares: &Vec<frost::SharePackage>,
    participants: Vec<ParticipantId>,
) -> BTreeMap<ParticipantId, Commitment> {
    assert_eq!(shares.len(), participants.len());
    participants
        .into_iter()
        .zip(shares)
        .map(|(participant_id, share)| {
            (
                participant_id,
                Commitment::from(share.share.commitment.0[0].clone()),
            )
        })
        .collect()
}

fn create_signing_commitments(
    commitments: Vec<frost::SigningCommitments>,
    participants: Vec<ParticipantId>,
) -> BTreeMap<ParticipantId, SigningCommitments> {
    assert_eq!(commitments.len(), participants.len());
    participants
        .into_iter()
        .zip(commitments)
        .map(|(participant_id, commitment)| {
            let signing_commitment = SigningCommitments {
                hiding: Commitment(jubjub::AffinePoint::from(commitment.hiding).to_bytes()),
                binding: Commitment(jubjub::AffinePoint::from(commitment.binding).to_bytes()),
            };
            (participant_id, signing_commitment)
        })
        .collect()
}
