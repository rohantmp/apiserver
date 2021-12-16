module github.com/loft-sh/apiserver

go 1.16

require (
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	go.opentelemetry.io/otel/trace v0.20.0
	k8s.io/apimachinery v0.23.0
	k8s.io/apiserver v0.23.0
	k8s.io/client-go v0.23.0
	k8s.io/gengo v0.0.0-20210813121822-485abfe95c7c
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.30.0
	k8s.io/kube-aggregator v0.23.0
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65
)
