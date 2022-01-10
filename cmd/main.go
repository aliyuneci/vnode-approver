package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aliyuneci/vnode-approver/pkg/certificate"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
)

const (
	kubeConfig = "/etc/vnode/kubeconfig.conf"
)

func main() {
	klog.InitFlags(flag.CommandLine)
	pflag.CommandLine.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	command := newApproverCommand()
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}

// newApproverCommand creates a new approver command
func newApproverCommand() *cobra.Command {
	return &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			client, err := buildKubeClient()
			if err != nil {
				panic(err)
			}

			informerFactory := informers.NewSharedInformerFactoryWithOptions(client, 60, informers.WithTweakListOptions(func(options *metav1.ListOptions) {
				options.FieldSelector = fields.Set{"spec.signerName": certificate.VNodeClientSignerName}.AsSelector().String()
			}))
			controller := certificate.NewCSRApprovingController(client, informerFactory.Certificates().V1().CertificateSigningRequests())

			stopCh := make(<-chan struct{})
			informerFactory.Start(stopCh)
			controller.Run(1, stopCh)
		},
	}
}

// buildKubeClient constructs the appropriate client for the informer
func buildKubeClient() (kubernetes.Interface, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("build config failed: %v", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build client failed: %v", err)
	}
	return client, nil
}
