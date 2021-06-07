module github.com/loft-sh/test

go 1.16

require (
	github.com/loft-sh/apiserver v0.0.0
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/apiserver v0.21.1
	k8s.io/gengo v0.0.0-20201214224949-b6c5ce23f027
	k8s.io/klog v1.0.0
)

replace github.com/loft-sh/apiserver => ../../../../../
