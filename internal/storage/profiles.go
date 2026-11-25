package storage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"ssh-packet-capture/internal/models"
)

// ProfileStore manages persistent SSH server profiles on disk.
type ProfileStore struct {
	mu       sync.RWMutex
	filePath string
	profiles []models.ServerProfile
}

// AppConfigDir returns the application data directory under %APPDATA% (or user config dir).
func AppConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	dir := filepath.Join(base, "NetProbeSSHCature")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func NewProfileStore() (*ProfileStore, error) {
	dir, err := AppConfigDir()
	if err != nil {
		return nil, err
	}
	store := &ProfileStore{
		filePath: filepath.Join(dir, "profiles.json"),
		profiles: []models.ServerProfile{},
	}
	_ = store.load()
	return store, nil
}

func (s *ProfileStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []models.ServerProfile
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	s.profiles = list
	return nil
}

func (s *ProfileStore) saveLocked() error {
	data, err := json.MarshalIndent(s.profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, data, 0o600)
}

func (s *ProfileStore) List() []models.ServerProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]models.ServerProfile, len(s.profiles))
	copy(out, s.profiles)
	return out
}

func (s *ProfileStore) Get(id string) (models.ServerProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, p := range s.profiles {
		if p.ID == id {
			return p, true
		}
	}
	return models.ServerProfile{}, false
}

func (s *ProfileStore) Save(p models.ServerProfile) (models.ServerProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.Port <= 0 {
		p.Port = 22
	}
	if p.Username == "" {
		p.Username = "root"
	}
	if p.AuthType == "" {
		p.AuthType = "password"
	}
	if p.ID == "" {
		p.ID = newID()
		s.profiles = append(s.profiles, p)
	} else {
		updated := false
		for i := range s.profiles {
			if s.profiles[i].ID == p.ID {
				s.profiles[i] = p
				updated = true
				break
			}
		}
		if !updated {
			s.profiles = append(s.profiles, p)
		}
	}
	if err := s.saveLocked(); err != nil {
		return p, err
	}
	return p, nil
}

func (s *ProfileStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := make([]models.ServerProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		if p.ID != id {
			next = append(next, p)
		}
	}
	s.profiles = next
	return s.saveLocked()
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
