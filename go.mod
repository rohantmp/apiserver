module github.com/loft-sh/apiserver

go 1.16

require (
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.4.0
	github.com/spf13/pflag v1.0.5
	go.opentelemetry.io/otel/trace v0.20.0
	k8s.io/apimachinery v0.24.0
	k8s.io/apiserver v0.24.0
	k8s.io/client-go v0.24.0
	k8s.io/gengo v0.0.0-20211129171323-c02415ce4185
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.60.1
	k8s.io/kube-aggregator v0.24.0
	k8s.io/kube-openapi v0.0.0-20220328201542-3ee0da9b0b42
)
