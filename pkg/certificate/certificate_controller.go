package certificate

import (
	"fmt"
	"time"

	"golang.org/x/time/rate"
	certificates "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	certificatesinformers "k8s.io/client-go/informers/certificates/v1"
	clientset "k8s.io/client-go/kubernetes"
	certificateslisters "k8s.io/client-go/listers/certificates/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

var (
	KeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc
)

type CertificateController struct {
	name       string
	kubeClient clientset.Interface
	csrLister  certificateslisters.CertificateSigningRequestLister
	csrsSynced cache.InformerSynced
	handler    func(*certificates.CertificateSigningRequest) error
	queue      workqueue.RateLimitingInterface
}

// NewCertificateController creates a new CertificateController.
func NewCertificateController(name string,
	kubeClient clientset.Interface,
	csrInformer certificatesinformers.CertificateSigningRequestInformer,
	handler func(*certificates.CertificateSigningRequest) error) *CertificateController {

	cc := &CertificateController{
		name:       name,
		kubeClient: kubeClient,
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 1000*time.Second),
			// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
		), "certificate"),
		handler: handler,
	}
	// Manage the addition/update of certificate requests
	csrInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certificates.CertificateSigningRequest)
			klog.V(3).Infof("Adding certificate request %s", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			oldCSR := old.(*certificates.CertificateSigningRequest)
			klog.V(3).Infof("Updating certificate request %s", oldCSR.Name)
			cc.enqueueCertificateRequest(new)
		},
		DeleteFunc: func(obj interface{}) {
			csr, ok := obj.(*certificates.CertificateSigningRequest)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.V(3).Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				csr, ok = tombstone.Obj.(*certificates.CertificateSigningRequest)
				if !ok {
					klog.V(3).Infof("Tombstone contained object that is not a CSR: %#v", obj)
					return
				}
			}
			klog.V(3).Infof("Deleting certificate request %s", csr.Name)
			cc.enqueueCertificateRequest(obj)
		},
	})
	cc.csrLister = csrInformer.Lister()
	cc.csrsSynced = csrInformer.Informer().HasSynced
	return cc
}

// Run the main goroutine responsible for watching and syncing jobs.
func (cc *CertificateController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer cc.queue.ShutDown()

	klog.V(2).Infof("Starting certificate controller %q", cc.name)
	defer klog.V(2).Infof("Shutting down certificate controller %q", cc.name)

	if !cache.WaitForNamedCacheSync(fmt.Sprintf("certificate-%s", cc.name), stopCh, cc.csrsSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(cc.worker, time.Second, stopCh)
	}

	<-stopCh
}

// worker runs a thread that dequeues CSRs, handles them, and marks them done.
func (cc *CertificateController) worker() {
	for cc.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (cc *CertificateController) processNextWorkItem() bool {
	cKey, quit := cc.queue.Get()
	if quit {
		return false
	}
	defer cc.queue.Done(cKey)

	if err := cc.syncFunc(cKey.(string)); err != nil {
		cc.queue.AddRateLimited(cKey)
		if _, ignorable := err.(ignorableError); !ignorable {
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with : %v", cKey, err))
		} else {
			klog.Errorf("Sync %v failed with : %v", cKey, err)
		}
		return true
	}

	cc.queue.Forget(cKey)
	return true

}

func (cc *CertificateController) enqueueCertificateRequest(obj interface{}) {
	key, err := KeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	cc.queue.Add(key)
}

func (cc *CertificateController) syncFunc(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).Infof("Finished syncing certificate request %q (%v)", key, time.Since(startTime))
	}()
	csr, err := cc.csrLister.Get(key)
	if errors.IsNotFound(err) {
		klog.V(2).Infof("csr has been deleted: %v", key)
		return nil
	}
	if err != nil {
		return err
	}

	if len(csr.Status.Certificate) > 0 {
		// no need to do anything because it already has a cert
		return nil
	}

	// need to operate on a copy so we don't mutate the csr in the shared cache
	csr = csr.DeepCopy()
	return cc.handler(csr)
}
