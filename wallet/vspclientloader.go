package wallet

import (
	"net/url"
	"strings"

	"github.com/monetarium/monetarium-wallet/errors"
	"github.com/monetarium/monetarium-wallet/internal/loggers"
)

// VSP loads or creates a package-global instance of the VSP client for a host.
// This allows clients to be created and reused across various subsystems.
// URLs that SameVSPHost considers equal share one client.
func (w *Wallet) VSP(cfg VSPClientConfig) (*VSPClient, error) {
	key := normalizeVSPURL(cfg.URL)
	w.vspClientsMu.Lock()
	defer w.vspClientsMu.Unlock()
	client, ok := w.vspClients[key]
	if ok {
		return client, nil
	}
	client, err := w.NewVSPClient(cfg, loggers.VspcLog, w.dialer)
	if err != nil {
		return nil, err
	}
	w.vspClients[key] = client
	return client, nil
}

// LookupVSP returns a previously-configured VSP client, if one has been created
// and registered with the VSP function.  Otherwise, a NotExist error is
// returned.
func (w *Wallet) LookupVSP(host string) (*VSPClient, error) {
	w.vspClientsMu.Lock()
	defer w.vspClientsMu.Unlock()
	client, ok := w.vspClients[normalizeVSPURL(host)]
	if !ok {
		err := errors.Errorf("VSP client for %q not found", host)
		return nil, errors.E(errors.NotExist, err)
	}
	return client, nil
}

// AllVSPs returns the list of all currently registered VSPs.
func (w *Wallet) AllVSPs() map[string]*VSPClient {
	// Create a copy to avoid callers mutating the list.
	w.vspClientsMu.Lock()
	defer w.vspClientsMu.Unlock()
	res := make(map[string]*VSPClient, len(w.vspClients))
	for host, client := range w.vspClients {
		res[host] = client
	}
	return res
}

// SameVSPHost reports whether two VSP URLs name the same VSP, ignoring ASCII
// case in the host and trailing slashes.
func SameVSPHost(a, b string) bool {
	return normalizeVSPURL(a) == normalizeVSPURL(b)
}

func normalizeVSPURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	// Only ASCII: Unicode lowercasing maps some letters to ones of another
	// DNS name (U+0130 to "i").
	u.Host = strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}
