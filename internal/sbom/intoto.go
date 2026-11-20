package sbom

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxLayerBytes bounds how much of an attestation layer is read.
const maxLayerBytes = MaxSBOMBytes

const (
	mtInToto    = "application/vnd.in-toto+json"
	mtDSSE      = "application/vnd.dsse.envelope.v1+json"
	mtBundle    = "application/vnd.dev.sigstore.bundle.v0.3+json"
	mtSPDX      = "application/spdx+json"
	mtCycloneDX = "application/vnd.cyclonedx+json"

	predSPDX      = "https://spdx.dev/Document"
	predCycloneDX = "https://cyclonedx.org/bom"
)

type statement struct {
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
}

// statementFromLayer reads one attestation layer and returns the SBOM predicate with its type and
// the sha256 subjects it covers (none for a bare SBOM document). Signatures are not verified: the
// image's publisher already controls the image itself, so a signature adds nothing ffs relies on.
func statementFromLayer(mediaType string, r io.Reader) (predType string, predicate []byte, subjects []string, err error) {
	body, err := io.ReadAll(io.LimitReader(r, maxLayerBytes+1))
	if err != nil {
		return "", nil, nil, err
	}
	if len(body) > maxLayerBytes {
		return "", nil, nil, fmt.Errorf("attestation layer exceeds %d bytes", maxLayerBytes)
	}
	switch mediaType {
	case mtSPDX:
		return predSPDX, body, nil, nil
	case mtCycloneDX:
		return predCycloneDX, body, nil, nil
	case mtInToto:
		return parseStatement(body)
	case mtDSSE:
		return parseEnvelope(body)
	case mtBundle:
		var b struct {
			DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
		}
		if err := json.Unmarshal(body, &b); err != nil {
			return "", nil, nil, err
		}
		if len(b.DSSEEnvelope) == 0 {
			return "", nil, nil, errors.New("sigstore bundle has no dsseEnvelope")
		}
		return parseEnvelope(b.DSSEEnvelope)
	}
	return "", nil, nil, fmt.Errorf("unsupported attestation media type %q", mediaType)
}

func parseEnvelope(b []byte) (string, []byte, []string, error) {
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return "", nil, nil, err
	}
	if e.PayloadType != mtInToto {
		return "", nil, nil, fmt.Errorf("unsupported DSSE payload type %q", e.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(e.Payload); err != nil {
			return "", nil, nil, fmt.Errorf("decoding DSSE payload: %w", err)
		}
	}
	return parseStatement(payload)
}

func parseStatement(b []byte) (string, []byte, []string, error) {
	var s statement
	if err := json.Unmarshal(b, &s); err != nil {
		return "", nil, nil, err
	}
	if !strings.HasPrefix(s.PredicateType, predSPDX) && !strings.HasPrefix(s.PredicateType, predCycloneDX) {
		return "", nil, nil, fmt.Errorf("unsupported predicate type %q", s.PredicateType)
	}
	if len(s.Predicate) == 0 {
		return "", nil, nil, errors.New("statement has no predicate")
	}
	var subjects []string
	for _, sub := range s.Subject {
		if h := sub.Digest["sha256"]; h != "" {
			subjects = append(subjects, strings.ToLower(h))
		}
	}
	return s.PredicateType, s.Predicate, subjects, nil
}

// creatorIsSyft reports whether an SPDX or CycloneDX document was produced by Syft.
func creatorIsSyft(predicate []byte) bool {
	var doc struct {
		CreationInfo struct {
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Metadata struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"metadata"`
	}
	if json.Unmarshal(predicate, &doc) != nil {
		return false
	}
	for _, c := range doc.CreationInfo.Creators {
		if strings.HasPrefix(c, "Tool: syft-") {
			return true
		}
	}
	type tool struct {
		Name string `json:"name"`
	}
	// CycloneDX 1.4 lists tools; 1.5+ nests them under tools.components.
	var legacy []tool
	if json.Unmarshal(doc.Metadata.Tools, &legacy) == nil {
		for _, t := range legacy {
			if t.Name == "syft" {
				return true
			}
		}
	}
	var modern struct {
		Components []tool `json:"components"`
	}
	if json.Unmarshal(doc.Metadata.Tools, &modern) == nil {
		for _, t := range modern.Components {
			if t.Name == "syft" {
				return true
			}
		}
	}
	return false
}
