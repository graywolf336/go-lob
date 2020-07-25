package lob

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

//WebhookEvent represents a webhook event
type WebhookEvent struct {
	ID          string           `json:"id"`
	Body        json.RawMessage  `json:"body"`
	ReferenceID string           `json:"reference_id"`
	EventType   WebhookEventType `json:"event_type"`
	DateCreated time.Time        `json:"date_created"`
	Object      string           `json:"object"`
}

//WebhookEventType represents the event type data for an event
type WebhookEventType struct {
	ID             string `json:"id"`
	EnabledForTest bool   `json:"enabled_for_test"`
	Resource       string `json:"resource"`
	Object         string `json:"object"`
}

// Errors returned by the webbook parsing
var (
	ErrInvalidHeader    = errors.New("webhook has invalid Lob-Signature header(s)")
	ErrNotTimestamped   = errors.New("no Lob-Signature-Timestamp header provided")
	ErrNotSigned        = errors.New("no Lob-Signature header provided")
	ErrNoValidSignature = errors.New("webhook has no valid signature")
	ErrTooOld           = errors.New("timestamp wasn't within tolerance")
)

//ConstructWebhookEvent constructs a new webhook event and enforces the header signature
func ConstructWebhookEvent(payload []byte, timestampHeader, signatureHeader, secret string, tolerance time.Duration) (WebhookEvent, error) {
	e := WebhookEvent{}

	if err := ValidateWebhookPayload(payload, timestampHeader, signatureHeader, secret, tolerance); err != nil {
		return e, err
	}

	if err := json.Unmarshal(payload, &e); err != nil {
		return e, fmt.Errorf("Failed to parse the webhook event body json: %s", err.Error())
	}

	return e, nil
}

//ValidateWebhookPayload valides the passed in payload and signature header
func ValidateWebhookPayload(payload []byte, timestampHeader, signatureHeader, secret string, tolerance time.Duration) error {
	if signatureHeader == "" {
		return ErrNotSigned
	}

	if err := hasValidTimestampWithTolerance(timestampHeader, tolerance); err != nil {
		return err
	}

	sig, err := hex.DecodeString(signatureHeader)
	if err != nil {
		return ErrInvalidHeader
	}

	computed := computeSignature(timestampHeader, payload, secret)

	if hmac.Equal(computed, sig) {
		return nil
	}

	return ErrNoValidSignature
}

func hasValidTimestampWithTolerance(timestampHeader string, tolerance time.Duration) error {
	if timestampHeader == "" {
		return ErrNotTimestamped
	}

	t, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return ErrInvalidHeader
	}

	// lob.com sends the epoch time with milliseconds
	sentTime := time.Unix(0, t*int64(time.Millisecond))

	if time.Since(sentTime) > tolerance {
		return ErrTooOld
	}

	return nil
}

func computeSignature(timestamp string, payload []byte, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))

	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)

	return mac.Sum(nil)
}
