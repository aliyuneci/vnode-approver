package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	capi "k8s.io/api/certificates/v1"
	certificates "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	organizationNotSystemNodesErr = fmt.Errorf("subject organization is not system:vnodes")
	commonNameNotSystemNode       = fmt.Errorf("subject common name does not begin with system:vnode:")
	dnsOrIPSANRequiredErr         = fmt.Errorf("DNS or IP subjectAltName is required")
	dnsSANNotAllowedErr           = fmt.Errorf("DNS subjectAltNames are not allowed")
	emailSANNotAllowedErr         = fmt.Errorf("Email subjectAltNames are not allowed")
	ipSANNotAllowedErr            = fmt.Errorf("IP subjectAltNames are not allowed")
	uriSANNotAllowedErr           = fmt.Errorf("URI subjectAltNames are not allowed")
)

var vnodeClientRequiredUsages = sets.NewString(
	string(capi.UsageDigitalSignature),
	string(capi.UsageKeyEncipherment),
	string(capi.UsageClientAuth),
)

// IgnorableError returns an error that we shouldn't handle (i.e. log) because
// it's spammy and usually user error. Instead we will log these errors at a
// higher log level. We still need to throw these errors to signal that the
// sync should be retried.
func IgnorableError(s string, args ...interface{}) ignorableError {
	return ignorableError(fmt.Sprintf(s, args...))
}

type ignorableError string

func (e ignorableError) Error() string {
	return string(e)
}

// IsCertificateRequestApproved returns true if a certificate request has the
// "Approved" condition and no "Denied" conditions; false otherwise.
func IsCertificateRequestApproved(csr *certificates.CertificateSigningRequest) bool {
	approved, denied := GetCertApprovalCondition(&csr.Status)
	return approved && !denied
}

// HasCondition returns true if the csr contains a condition of the specified type with a status that is set to True or is empty
func HasTrueCondition(csr *certificates.CertificateSigningRequest, conditionType certificates.RequestConditionType) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == conditionType && (len(c.Status) == 0 || c.Status == v1.ConditionTrue) {
			return true
		}
	}
	return false
}

// GetCertApprovalCondition is used to cert status
func GetCertApprovalCondition(status *certificates.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == certificates.CertificateApproved {
			approved = true
		}
		if c.Type == certificates.CertificateDenied {
			denied = true
		}
	}
	return
}

// ParseCSR extracts the CSR from the bytes and decodes it.
func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}

// Returns 0 for resyncPeriod in case resyncing is not needed.
func NoResyncPeriodFunc() time.Duration {
	return 0
}
