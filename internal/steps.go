package internal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/GoCodeAlone/libsignal-go/address"
	"github.com/GoCodeAlone/libsignal-go/curve"
	"github.com/GoCodeAlone/libsignal-go/fingerprint"
	"github.com/GoCodeAlone/libsignal-go/kem"
	"github.com/GoCodeAlone/libsignal-go/protocol"
	"github.com/GoCodeAlone/libsignal-go/session"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"

	contracts "github.com/GoCodeAlone/workflow-plugin-signal/internal/contracts"
)

// ExecuteSignalFingerprint computes a Signal safety number and scannable
// fingerprint from serialized identity public keys.
func ExecuteSignalFingerprint(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.SignalFingerprintConfig, *contracts.SignalFingerprintInput],
) (*sdk.TypedStepResult[*contracts.SignalFingerprintOutput], error) {
	_ = ctx
	if req.Input == nil {
		return nil, fmt.Errorf("signal fingerprint: missing input")
	}
	version := firstNonZero(req.Input.GetVersion(), req.Config.GetVersion())
	iterations := firstNonZero(req.Input.GetIterations(), req.Config.GetIterations())
	localKey, err := decodePublicKey(req.Input.GetLocalKey())
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: localKey: %w", err)
	}
	remoteKey, err := decodePublicKey(req.Input.GetRemoteKey())
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: remoteKey: %w", err)
	}
	fp, err := fingerprint.New(version, iterations, []byte(req.Input.GetLocalId()), localKey, []byte(req.Input.GetRemoteId()), remoteKey)
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: compute: %w", err)
	}
	scannable, err := fp.Scannable.Serialize()
	if err != nil {
		return nil, fmt.Errorf("signal fingerprint: serialize scannable: %w", err)
	}
	return &sdk.TypedStepResult[*contracts.SignalFingerprintOutput]{
		Output: &contracts.SignalFingerprintOutput{
			Display:      fp.DisplayString(),
			ScannableHex: hex.EncodeToString(scannable),
		},
	}, nil
}

func ExecuteSignalSessionPrepare(
	_ context.Context,
	req sdk.TypedStepRequest[*contracts.SessionPrepareConfig, *contracts.SessionPrepareInput],
) (*sdk.TypedStepResult[*contracts.SessionPrepareOutput], error) {
	identity, err := lookupSignalIdentity(firstNonEmpty(req.Input.GetIdentityRef(), req.Config.GetIdentityRef()))
	if err != nil {
		return nil, fmt.Errorf("signal session prepare: %w", err)
	}
	signedSig, err := identity.identity.PrivateKey.CalculateSignature(rand.Reader, identity.signedPre.PublicKey.Serialize())
	if err != nil {
		return nil, fmt.Errorf("signal session prepare: signed pre-key signature: %w", err)
	}
	kyberSig, err := identity.identity.PrivateKey.CalculateSignature(rand.Reader, identity.kyber.PublicKey.Serialize())
	if err != nil {
		return nil, fmt.Errorf("signal session prepare: kyber pre-key signature: %w", err)
	}
	return &sdk.TypedStepResult[*contracts.SessionPrepareOutput]{
		Output: &contracts.SessionPrepareOutput{
			Bundle: &contracts.PreKeyBundle{
				IdentityRef:           identity.ref,
				LocalId:               identity.localID,
				DeviceId:              identity.deviceID,
				RegistrationId:        identity.registrationID,
				PreKeyId:              identity.preKeyID,
				PreKey:                hex.EncodeToString(identity.oneTime.PublicKey.Serialize()),
				SignedPreKeyId:        identity.signedPreKeyID,
				SignedPreKey:          hex.EncodeToString(identity.signedPre.PublicKey.Serialize()),
				SignedPreKeySignature: hex.EncodeToString(signedSig),
				KyberPreKeyId:         identity.kyberPreKeyID,
				KyberPreKey:           hex.EncodeToString(identity.kyber.PublicKey.Serialize()),
				KyberPreKeySignature:  hex.EncodeToString(kyberSig),
				IdentityKey:           hex.EncodeToString(identity.identity.PublicKey.Serialize()),
			},
		},
	}, nil
}

func ExecuteSignalEncrypt(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.SignalEncryptConfig, *contracts.SignalEncryptInput],
) (*sdk.TypedStepResult[*contracts.SignalEncryptOutput], error) {
	if req.Input == nil {
		return nil, fmt.Errorf("signal encrypt: missing input")
	}
	local, err := lookupSignalIdentity(firstNonEmpty(req.Input.GetIdentityRef(), req.Config.GetIdentityRef()))
	if err != nil {
		return nil, fmt.Errorf("signal encrypt: %w", err)
	}
	bundle := req.Input.GetRemoteBundle()
	if bundle == nil {
		return nil, fmt.Errorf("signal encrypt: remote_bundle is required")
	}
	remoteID := firstNonEmpty(req.Input.GetRemoteId(), bundle.GetLocalId())
	remoteDeviceID := firstNonZero(req.Input.GetRemoteDeviceId(), bundle.GetDeviceId())
	remoteAddr, err := protocolAddress(remoteID, remoteDeviceID)
	if err != nil {
		return nil, fmt.Errorf("signal encrypt: remote address: %w", err)
	}
	sessionBundle, err := preKeyBundleFromContract(bundle)
	if err != nil {
		return nil, fmt.Errorf("signal encrypt: remote bundle: %w", err)
	}
	if err := session.ProcessPreKeyBundle(ctx, rand.Reader, remoteAddr, sessionBundle, local.sessionStore, local.identityStore); err != nil {
		return nil, fmt.Errorf("signal encrypt: process pre-key bundle: %w", err)
	}
	signalMsg, preKeyMsg, err := session.Encrypt(ctx, req.Input.GetPlaintext(), remoteAddr, local.sessionStore, local.identityStore, nil, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signal encrypt: encrypt: %w", err)
	}
	messageType := "signal"
	var ciphertext []byte
	if preKeyMsg != nil {
		messageType = "prekey"
		ciphertext = preKeyMsg.Serialize()
	} else {
		ciphertext = signalMsg.Serialize()
	}
	return &sdk.TypedStepResult[*contracts.SignalEncryptOutput]{
		Output: &contracts.SignalEncryptOutput{
			Envelope: &contracts.SignalEnvelope{
				SenderId:          local.localID,
				SenderDeviceId:    local.deviceID,
				RecipientId:       remoteID,
				RecipientDeviceId: remoteDeviceID,
				MessageType:       messageType,
				Ciphertext:        ciphertext,
			},
		},
	}, nil
}

func ExecuteSignalDecrypt(
	ctx context.Context,
	req sdk.TypedStepRequest[*contracts.SignalDecryptConfig, *contracts.SignalDecryptInput],
) (*sdk.TypedStepResult[*contracts.SignalDecryptOutput], error) {
	if req.Input == nil {
		return nil, fmt.Errorf("signal decrypt: missing input")
	}
	requiredPrincipal := req.Config.GetRequiredPrincipal()
	if requiredPrincipal != "" && req.Input.GetPrincipal() != requiredPrincipal {
		return decryptDenied("principal is not authorized"), nil
	}
	local, err := lookupSignalIdentity(firstNonEmpty(req.Input.GetIdentityRef(), req.Config.GetIdentityRef()))
	if err != nil {
		return nil, fmt.Errorf("signal decrypt: %w", err)
	}
	envelope := req.Input.GetEnvelope()
	if envelope == nil {
		return nil, fmt.Errorf("signal decrypt: envelope is required")
	}
	senderAddr, err := protocolAddress(envelope.GetSenderId(), envelope.GetSenderDeviceId())
	if err != nil {
		return nil, fmt.Errorf("signal decrypt: sender address: %w", err)
	}

	var signalMsg *protocol.SignalMessage
	switch envelope.GetMessageType() {
	case "prekey":
		preKeyMsg, err := protocol.DeserializePreKeySignalMessage(envelope.GetCiphertext())
		if err != nil {
			return nil, fmt.Errorf("signal decrypt: parse pre-key message: %w", err)
		}
		state, err := session.InitializeBobSession(session.BobParams{
			OurIdentity:   local.identity,
			OurSignedPre:  local.signedPre,
			OurOneTime:    &local.oneTime,
			OurKyber:      local.kyber,
			TheirIdentity: preKeyMsg.IdentityKey(),
			TheirBaseKey:  preKeyMsg.BaseKey(),
			KyberCipher:   preKeyMsg.KyberCiphertext(),
		})
		if err != nil {
			return nil, fmt.Errorf("signal decrypt: initialize session: %w", err)
		}
		if err := local.sessionStore.StoreSession(ctx, senderAddr, session.NewSessionRecord(state)); err != nil {
			return nil, fmt.Errorf("signal decrypt: store session: %w", err)
		}
		signalMsg = preKeyMsg.Message()
	case "signal":
		msg, err := protocol.DeserializeSignalMessage(envelope.GetCiphertext())
		if err != nil {
			return nil, fmt.Errorf("signal decrypt: parse signal message: %w", err)
		}
		signalMsg = msg
	default:
		return nil, fmt.Errorf("signal decrypt: unsupported message_type %q", envelope.GetMessageType())
	}

	plaintext, err := session.Decrypt(ctx, signalMsg, senderAddr, local.sessionStore, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signal decrypt: decrypt: %w", err)
	}
	return &sdk.TypedStepResult[*contracts.SignalDecryptOutput]{
		Output: &contracts.SignalDecryptOutput{Plaintext: plaintext},
	}, nil
}

func decodePublicKey(value string) (curve.PublicKey, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return curve.PublicKey{}, err
	}
	return curve.DeserializePublicKey(raw)
}

func firstNonZero(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func protocolAddress(name string, deviceID uint32) (address.ProtocolAddress, error) {
	device, err := address.NewDeviceID(deviceID)
	if err != nil {
		return address.ProtocolAddress{}, err
	}
	return address.NewProtocolAddress(name, device), nil
}

func preKeyBundleFromContract(bundle *contracts.PreKeyBundle) (*session.PreKeyBundle, error) {
	preKey, err := decodePublicKey(bundle.GetPreKey())
	if err != nil {
		return nil, fmt.Errorf("pre_key: %w", err)
	}
	signedPreKey, err := decodePublicKey(bundle.GetSignedPreKey())
	if err != nil {
		return nil, fmt.Errorf("signed_pre_key: %w", err)
	}
	kyberPreKey, err := decodeKEMPublicKey(bundle.GetKyberPreKey())
	if err != nil {
		return nil, fmt.Errorf("kyber_pre_key: %w", err)
	}
	identityKey, err := decodePublicKey(bundle.GetIdentityKey())
	if err != nil {
		return nil, fmt.Errorf("identity_key: %w", err)
	}
	signedSig, err := hex.DecodeString(bundle.GetSignedPreKeySignature())
	if err != nil {
		return nil, fmt.Errorf("signed_pre_key_signature: %w", err)
	}
	kyberSig, err := hex.DecodeString(bundle.GetKyberPreKeySignature())
	if err != nil {
		return nil, fmt.Errorf("kyber_pre_key_signature: %w", err)
	}
	preKeyID := bundle.GetPreKeyId()
	return session.NewPreKeyBundle(session.PreKeyBundleParams{
		RegistrationID:  bundle.GetRegistrationId(),
		DeviceID:        bundle.GetDeviceId(),
		PreKeyID:        &preKeyID,
		PreKey:          &preKey,
		SignedPreKeyID:  bundle.GetSignedPreKeyId(),
		SignedPreKey:    signedPreKey,
		SignedPreKeySig: signedSig,
		KyberPreKeyID:   bundle.GetKyberPreKeyId(),
		KyberPreKey:     kyberPreKey,
		KyberPreKeySig:  kyberSig,
		IdentityKey:     identityKey,
	})
}

func decodeKEMPublicKey(value string) (kem.PublicKey, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return kem.PublicKey{}, err
	}
	return kem.DeserializePublicKey(raw)
}

func decryptDenied(message string) *sdk.TypedStepResult[*contracts.SignalDecryptOutput] {
	return &sdk.TypedStepResult[*contracts.SignalDecryptOutput]{
		Output: &contracts.SignalDecryptOutput{
			Denied: true,
			Error:  message,
		},
	}
}
