module github.com/loft-sh/test

go 1.16

require (
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/loft-sh/apiserver v0.0.0
	k8s.io/apimachinery v0.23.0
	k8s.io/apiserver v0.23.0
	k8s.io/client-go v0.23.0
	k8s.io/gengo v0.0.0-20210813121822-485abfe95c7c
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.23.0
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65
)

replace github.com/loft-sh/apiserver => ../../../../../
