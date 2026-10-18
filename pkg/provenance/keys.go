package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
)

// GenerateKeyPair generates a new cryptographic Ed25519 public/private keypair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519 keygen failed: %w", err)
	}
	return pub, priv, nil
}

// GenerateKeyPairHex returns hex-encoded string representations of an Ed25519 keypair.
func GenerateKeyPairHex() (pubHex string, privHex string, err error) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// KeyRegistry manages public keys for registered agents and upstream MCP servers.
type KeyRegistry struct {
	agentKeys  map[string]ed25519.PublicKey
	serverKeys map[string]ed25519.PublicKey
	revoked    map[string]bool
	mu         sync.RWMutex
}

// NewKeyRegistry initializes an empty key registry.
func NewKeyRegistry() *KeyRegistry {
	return &KeyRegistry{
		agentKeys:  make(map[string]ed25519.PublicKey),
		serverKeys: make(map[string]ed25519.PublicKey),
		revoked:    make(map[string]bool),
	}
}

// RegisterAgentKey registers an Ed25519 public key for an agent.
func (kr *KeyRegistry) RegisterAgentKey(agentID string, pubKey ed25519.PublicKey) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.agentKeys[agentID] = pubKey
	delete(kr.revoked, agentID)
}

// RegisterAgentKeyHex registers a hex-encoded public key for an agent.
func (kr *KeyRegistry) RegisterAgentKeyHex(agentID string, pubKeyHex string) error {
	b, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key: %w", err)
	}
	kr.RegisterAgentKey(agentID, ed25519.PublicKey(b))
	return nil
}

// GetAgentKey retrieves the public key for an agent.
func (kr *KeyRegistry) GetAgentKey(agentID string) (ed25519.PublicKey, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.revoked[agentID] {
		return nil, false
	}
	k, ok := kr.agentKeys[agentID]
	return k, ok
}

// RegisterServerKey registers an Ed25519 public key for an upstream MCP server.
func (kr *KeyRegistry) RegisterServerKey(serverID string, pubKey ed25519.PublicKey) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.serverKeys[serverID] = pubKey
}

// RegisterServerKeyHex registers a hex-encoded public key for an upstream MCP server.
func (kr *KeyRegistry) RegisterServerKeyHex(serverID string, pubKeyHex string) error {
	b, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 server public key: %w", err)
	}
	kr.RegisterServerKey(serverID, ed25519.PublicKey(b))
	return nil
}

// GetServerKey retrieves the public key for an upstream MCP server.
func (kr *KeyRegistry) GetServerKey(serverID string) (ed25519.PublicKey, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	k, ok := kr.serverKeys[serverID]
	return k, ok
}

// RevokeKey revokes access for an agent or server.
func (kr *KeyRegistry) RevokeKey(entityID string) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.revoked[entityID] = true
}
