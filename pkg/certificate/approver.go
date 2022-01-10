package certificate

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"

	authorization "k8s.io/api/authorization/v1"
	capi "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	certificatesinformers "k8s.io/client-go/informers/certificates/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	VNodeClientSignerName   = "kubernetes.io/kube-apiserver-client"
	SubjectCommonNamePrefix = "system:vnode"
	SubjectOrganization     = "system:vnodes"
)

type csrRecognizer struct {
	recognize      func(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool
	permission     authorization.ResourceAttributes
	successMessage string
}

type sarApprover struct {
	client      clientset.Interface
	recognizers []csrRecognizer
}

// NewCSRApprovingController creates a new CSRApprovingController.
func NewCSRApprovingController(client clientset.Interface, csrInformer certificatesinformers.CertificateSigningRequestInformer) *CertificateController {
	approver := &sarApprover{
		client:      client,
		recognizers: recognizers(),
	}
	return NewCertificateController(
		"csrapproving",
		client,
		csrInformer,
		approver.handle,
	)
}

// recognizers
func recognizers() []csrRecognizer {
	recognizers := []csrRecognizer{
		{
			recognize:      isSelfNodeClientCert,
			permission:     authorization.ResourceAttributes{Group: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "create", Subresource: "selfnodeclient"},
			successMessage: "Auto approving self vnode client certificate after SubjectAccessReview.",
		},
		{
			recognize:      isNodeClientCert,
			permission:     authorization.ResourceAttributes{Group: "certificates.k8s.io", Resource: "certificatesigningrequests", Verb: "create", Subresource: "nodeclient"},
			successMessage: "Auto approving vnode client certificate after SubjectAccessReview.",
		},
	}
	return recognizers
}

// handle is used to approve csr
func (a *sarApprover) handle(csr *capi.CertificateSigningRequest) error {
	if len(csr.Status.Certificate) != 0 {
		return nil
	}
	if approved, denied := GetCertApprovalCondition(&csr.Status); approved || denied {
		return nil
	}
	x509cr, err := ParseCSR(csr.Spec.Request)
	if err != nil {
		return fmt.Errorf("unable to parse csr %q: %v", csr.Name, err)
	}

	tried := []string{}

	for _, r := range a.recognizers {
		if !r.recognize(csr, x509cr) {
			continue
		}

		tried = append(tried, r.permission.Subresource)

		approved, err := a.authorize(csr, r.permission)
		if err != nil {
			return err
		}
		if approved {
			appendApprovalCondition(csr, r.successMessage)
			_, err = a.client.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.Background(), csr.Name, csr, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("error updating approval for csr: %v", err)
			}
			return nil
		}
	}

	if len(tried) != 0 {
		return IgnorableError("recognized csr %q as %v but subject access review was not approved", csr.Name, tried)
	}

	return nil
}

// authorize is used to determine whether to authorize the csr
func (a *sarApprover) authorize(csr *capi.CertificateSigningRequest, rattrs authorization.ResourceAttributes) (bool, error) {
	extra := make(map[string]authorization.ExtraValue)
	for k, v := range csr.Spec.Extra {
		extra[k] = authorization.ExtraValue(v)
	}

	sar := &authorization.SubjectAccessReview{
		Spec: authorization.SubjectAccessReviewSpec{
			User:               csr.Spec.Username,
			UID:                csr.Spec.UID,
			Groups:             csr.Spec.Groups,
			Extra:              extra,
			ResourceAttributes: &rattrs,
		},
	}
	sar, err := a.client.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), sar, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return sar.Status.Allowed, nil
}

// appendApprovalCondition is used to fill csr status
func appendApprovalCondition(csr *capi.CertificateSigningRequest, message string) {
	csr.Status.Conditions = append(csr.Status.Conditions, capi.CertificateSigningRequestCondition{
		Type:    capi.CertificateApproved,
		Status:  corev1.ConditionTrue,
		Reason:  "AutoApproved",
		Message: message,
	})
}

func isSelfNodeClientCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if csr.Spec.Username != x509cr.Subject.CommonName {
		return false
	}
	return isNodeClientCert(csr, x509cr)
}

func isNodeClientCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if csr.Spec.SignerName != VNodeClientSignerName {
		return false
	}
	return IsVNodeClientCSR(x509cr, usagesToSet(csr.Spec.Usages))
}

func usagesToSet(usages []capi.KeyUsage) sets.String {
	result := sets.NewString()
	for _, usage := range usages {
		result.Insert(string(usage))
	}
	return result
}

// IsVNodeClientCSR verify whether the csr request is a vnode client
func IsVNodeClientCSR(req *x509.CertificateRequest, usages sets.String) bool {
	if err := ValidateVNodeClientCSR(req, usages); err != nil {
		klog.Errorf("validate vnode client csr failed: %v", err)
		return false
	}
	klog.V(2).Infof("validate vnode client csr successfully")
	return ValidateVNodeClientCSR(req, usages) == nil
}

// ValidateVNodeClientCSR validate vnode client csr
func ValidateVNodeClientCSR(req *x509.CertificateRequest, usages sets.String) error {
	if !reflect.DeepEqual([]string{SubjectOrganization}, req.Subject.Organization) {
		return organizationNotSystemNodesErr
	}

	if len(req.DNSNames) > 0 {
		return dnsSANNotAllowedErr
	}

	if len(req.EmailAddresses) > 0 {
		return emailSANNotAllowedErr
	}

	if len(req.IPAddresses) > 0 {
		return ipSANNotAllowedErr
	}

	if len(req.URIs) > 0 {
		return uriSANNotAllowedErr
	}

	if !strings.HasPrefix(req.Subject.CommonName, SubjectCommonNamePrefix) {
		return commonNameNotSystemNode
	}

	if !vnodeClientRequiredUsages.Equal(usages) {
		return fmt.Errorf("usages did not match %v", vnodeClientRequiredUsages.List())
	}

	return nil
}
