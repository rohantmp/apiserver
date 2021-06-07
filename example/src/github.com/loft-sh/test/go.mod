module github.com/loft-sh/test

go 1.16

require (
	github.com/go-openapi/spec v0.19.5
	github.com/loft-sh/apiserver v0.0.0
	k8s.io/api v0.21.1 // indirect
	k8s.io/apimachinery v0.21.1
	k8s.io/apiserver v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/gengo v0.0.0-20201214224949-b6c5ce23f027
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.21.1
	k8s.io/kube-openapi v0.0.0-20210527164424-3c818078ee3d
)

replace (
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7 
	github.com/go-openapi/jsonpointer => github.com/go-openapi/jsonpointer v0.19.3
	github.com/go-openapi/jsonreference => github.com/go-openapi/jsonreference v0.19.3
	github.com/go-openapi/swag => github.com/go-openapi/swag v0.19.5
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1
	github.com/loft-sh/apiserver => ../../../../../
)
