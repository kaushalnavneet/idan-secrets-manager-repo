package publiccerts

import (
	"fmt"
	common "github.ibm.com/security-services/secrets-manager-vault-plugins-common"
	"time"
)

// DNSProviderManual is an implementation of the ChallengeProvider interface.
type DNSProviderManual struct {
}

// NewManualDNSProvider returns a DNSProviderManual instance.
func NewManualDNSProvider() *DNSProviderManual {
	return &DNSProviderManual{}
}

// Present prints instructions for manually creating the TXT record.
func (*DNSProviderManual) Present(domain, token, keyAuth string) error {
	logStart := dnsProviderManual + presentFunc + domain
	common.Logger().Info(logStart + endSetChallenge)
	return nil

}

// CleanUp prints instructions for manually removing the TXT record.
func (*DNSProviderManual) CleanUp(domain, token, keyAuth string) error {
	logStart := dnsProviderManual + cleanupFunc + domain
	common.Logger().Info(logStart + endCleanup)
	return nil
}

func (*DNSProviderManual) Timeout() (timeout, interval time.Duration) {
	logStart := dnsProviderManual + timeoutFunc
	common.Logger().Info(logStart + fmt.Sprintf(timeoutsLog, PropagationTimeoutManual, PollingIntervalManual))
	return PropagationTimeoutManual, PollingIntervalManual
}
