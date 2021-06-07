/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiserver

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/loft-sh/apiserver/pkg/admission"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/util/webhook"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/loft-sh/apiserver/pkg/apiserver"
	"github.com/loft-sh/apiserver/pkg/builders"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/admission/plugin/namespace/lifecycle"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	openapinamer "k8s.io/apiserver/pkg/endpoints/openapi"
	"k8s.io/apiserver/pkg/server"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/util/feature"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
	aggregatorapiserver "k8s.io/kube-aggregator/pkg/apiserver"
	openapi "k8s.io/kube-openapi/pkg/common"
)

var GetOpenApiDefinition openapi.GetOpenAPIDefinitions

type ServerOptions struct {
	RecommendedOptions     *genericoptions.RecommendedOptions
	APIBuilders            []*builders.APIGroupBuilder
	InsecureServingOptions *genericoptions.DeprecatedInsecureServingOptionsWithLoopback

	PrintBearerToken bool
	PrintOpenapi     bool
	RunDelegatedAuth bool
	PostStartHooks   []PostStartHook
}

type PostStartHook struct {
	Fn   genericapiserver.PostStartHookFunc
	Name string
}

type StartOptions struct {
	Apis       []*builders.APIGroupBuilder
	Authorizer authorizer.Authorizer

	Openapidefs openapi.GetOpenAPIDefinitions
	Title       string
	Version     string

	APIServerVersion *version.Info

	TweakServerConfig func(serverOptions *ServerOptions)
	TweakConfigFuncs  []func(apiServer *apiserver.Config) error

	//FlagConfigFunc handles user-defined flags
	FlagConfigFuncs []func(*cobra.Command) error
}

func StartApiServerWithOptions(opts *StartOptions) error {
	GetOpenApiDefinition = opts.Openapidefs

	signalCh := genericapiserver.SetupSignalHandler()
	// To disable providers, manually specify the list provided by getKnownProviders()
	cmd, _ := NewCommandStartServer(opts.Apis, opts.APIServerVersion, signalCh, opts.Authorizer, opts.Title, opts.Version, opts.TweakServerConfig, opts.TweakConfigFuncs...)

	errors := []error{}
	for _, ff := range opts.FlagConfigFuncs {
		if err := ff(cmd); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) != 0 {
		return utilerrors.NewAggregate(errors)
	}

	cmd.Flags().AddFlagSet(pflag.CommandLine)
	if err := cmd.Execute(); err != nil {
		return err
	}

	return nil
}

func NewServerOptions(title, version string, b []*builders.APIGroupBuilder) *ServerOptions {
	versions := []schema.GroupVersion{}
	for _, b := range b {
		versions = append(versions, b.GetLegacyCodec()...)
	}

	builders.Codecs = serializer.NewCodecFactory(builders.Scheme, func(options *serializer.CodecFactoryOptions) {
		options.Strict = true
	})
	o := &ServerOptions{
		RecommendedOptions: genericoptions.NewRecommendedOptions(
			"",
			builders.Codecs.LegacyCodec(versions...),
		),
		APIBuilders:      b,
		RunDelegatedAuth: false,
	}

	// We don't use etcd
	o.RecommendedOptions.Etcd = nil
	o.RecommendedOptions.Admission = genericoptions.NewAdmissionOptions()
	o.RecommendedOptions.Admission.DefaultOffPlugins = sets.String{lifecycle.PluginName: sets.Empty{}}

	// TODO don't hardcode this
	o.RecommendedOptions.SecureServing.BindPort = 8443

	o.RecommendedOptions.Authorization.RemoteKubeConfigFileOptional = true
	o.RecommendedOptions.Authentication.RemoteKubeConfigFileOptional = true
	o.InsecureServingOptions = func() *genericoptions.DeprecatedInsecureServingOptionsWithLoopback {
		o := genericoptions.DeprecatedInsecureServingOptions{}
		return o.WithLoopback()
	}()

	return o
}

// NewCommandStartMaster provides a CLI handler for 'start master' command
func NewCommandStartServer(builders []*builders.APIGroupBuilder, APIServerVersion *version.Info, stopCh <-chan struct{}, authorizer authorizer.Authorizer, title, version string, tweakServerConfig func(serverOptions *ServerOptions), tweakConfigFuncs ...func(apiServer *apiserver.Config) error) (*cobra.Command, *ServerOptions) {
	o := NewServerOptions(title, version, builders)

	tweakServerConfig(o)

	// for pluginName := range AggregatedAdmissionPlugins {
	//	o.RecommendedOptions.Admission.RecommendedPluginOrder = append(o.RecommendedOptions.Admission.RecommendedPluginOrder, pluginName)
	// }

	klogFlags := flag.NewFlagSet("klog", flag.ExitOnError)
	// Support overrides
	cmd := &cobra.Command{
		Short: "Launch an API server",
		Long:  "Launch an API server",
		RunE: func(c *cobra.Command, args []string) error {
			// TODO: remove it after upgrading to 1.13+
			// Sync the glog and klog flags.
			klogFlags.VisitAll(func(f *flag.Flag) {
				goFlag := flag.CommandLine.Lookup(f.Name)
				if goFlag != nil {
					goFlag.Value.Set(f.Value.String())
				}
			})

			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}

			if err := o.RunServer(APIServerVersion, stopCh, authorizer, title, version, tweakConfigFuncs...); err != nil {
				return err
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&o.PrintBearerToken, "print-bearer-token", false, "Print a curl command with the bearer token to test the server")
	flags.BoolVar(&o.PrintOpenapi, "print-openapi", false, "Print the openapi json and exit")
	flags.BoolVar(&o.RunDelegatedAuth, "delegated-auth", false, "Setup delegated auth")
	o.RecommendedOptions.AddFlags(flags)
	o.InsecureServingOptions.AddFlags(flags)

	feature.DefaultMutableFeatureGate.AddFlag(flags)

	klog.InitFlags(klogFlags)
	flags.AddGoFlagSet(klogFlags)

	return cmd, o
}

func (o ServerOptions) Validate(args []string) error {
	return nil
}

func (o *ServerOptions) Complete() error {
	return nil
}

func applyOptions(config *genericapiserver.Config, applyTo ...func(*genericapiserver.Config) error) error {
	for _, fn := range applyTo {
		if err := fn(config); err != nil {
			return err
		}
	}

	return nil
}

func (o ServerOptions) Config(tweakConfigFuncs ...func(config *apiserver.Config) error) (*apiserver.Config, error) {
	// switching pagination according to the feature-gate
	// o.RecommendedOptions.Etcd.StorageConfig.Paging = feature.DefaultFeatureGate.Enabled(features.APIListChunking)

	// TODO have a "real" external address
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, nil); err != nil {

		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(builders.Codecs)

	// TODO(yue9944882): for backward-compatibility, a loopback client is optional in the server. But if the client is
	//  missing, server will have to lose the following additional functionalities:
	//  - 	all admission controllers: almost all admission controllers relies on injecting loopback client or loopback
	//  	informers.
	//  -	delegated authentication/authorization: the server will not be able to request kube-apiserver for delegated
	//		authn/authz apis.
	loopbackClientOptional := true
	loopbackKubeConfig, kubeInformerFactory, err := o.buildLoopback()
	if loopbackClientOptional {
		if err != nil {
			klog.Warningf("attempting to instantiate loopback client but failed: %v", err)
		} else {
			serverConfig.LoopbackClientConfig = loopbackKubeConfig
			serverConfig.SharedInformerFactory = kubeInformerFactory
		}
	} else {
		if err != nil {
			return nil, err
		}
	}

	if os.Getenv("DISABLE_ADMISSION_WEBHOOKS") != "true" && serverConfig.LoopbackClientConfig != nil {
		proxyTransport := CreateNodeDialer()
		admissionConfig := &admission.Config{
			ExternalInformers:    kubeInformerFactory,
			LoopbackClientConfig: serverConfig.LoopbackClientConfig,
		}
		serviceResolver := buildServiceResolver(false, serverConfig.LoopbackClientConfig.Host, kubeInformerFactory)
		pluginInitializers, admissionPostStartHook, err := admissionConfig.New(proxyTransport, serverConfig.EgressSelector, serviceResolver)
		if err != nil {
			return nil, fmt.Errorf("failed to create admission plugin initializer: %v", err)
		}
		if err := serverConfig.AddPostStartHook("start-kube-apiserver-admission-initializer", admissionPostStartHook); err != nil {
			return nil, err
		}

		err = o.RecommendedOptions.Admission.ApplyTo(
			&serverConfig.Config,
			kubeInformerFactory,
			serverConfig.LoopbackClientConfig,
			utilfeature.DefaultFeatureGate,
			pluginInitializers...)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize admission: %v", err)
		}
	}

	err = applyOptions(
		&serverConfig.Config,
		// o.RecommendedOptions.Etcd.ApplyTo,
		func(cfg *genericapiserver.Config) error {
			return o.RecommendedOptions.SecureServing.ApplyTo(&cfg.SecureServing, &cfg.LoopbackClientConfig)
		},
		func(cfg *genericapiserver.Config) error {
			return o.RecommendedOptions.Audit.ApplyTo(
				&serverConfig.Config,
			)
		},
		o.RecommendedOptions.Features.ApplyTo,
	)
	if err != nil {
		return nil, err
	}

	var insecureServingInfo *genericapiserver.DeprecatedInsecureServingInfo
	if err := o.InsecureServingOptions.ApplyTo(&insecureServingInfo, &serverConfig.LoopbackClientConfig); err != nil {
		return nil, err
	}
	config := &apiserver.Config{
		RecommendedConfig:   serverConfig,
		InsecureServingInfo: insecureServingInfo,
		PostStartHooks:      make(map[string]genericapiserver.PostStartHookFunc),
	}

	o.RecommendedOptions.Authentication.ApplyTo(&serverConfig.Authentication, serverConfig.Config.SecureServing, serverConfig.Config.OpenAPIConfig)
	o.RecommendedOptions.Authorization.ApplyTo(&serverConfig.Authorization)

	for _, tweakConfigFunc := range tweakConfigFuncs {
		if err := tweakConfigFunc(config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

// CreateNodeDialer creates the dialer infrastructure to connect to the nodes.
func CreateNodeDialer() *http.Transport {
	// Setup nodeTunneler if needed
	var proxyDialerFn utilnet.DialFunc

	// Proxying to pods and services is IP-based... don't expect to be able to verify the hostname
	proxyTLSClientConfig := &tls.Config{InsecureSkipVerify: true}
	proxyTransport := utilnet.SetTransportDefaults(&http.Transport{
		DialContext:     proxyDialerFn,
		TLSClientConfig: proxyTLSClientConfig,
	})
	return proxyTransport
}

func buildServiceResolver(enabledAggregatorRouting bool, hostname string, informer informers.SharedInformerFactory) webhook.ServiceResolver {
	var serviceResolver webhook.ServiceResolver
	if enabledAggregatorRouting {
		serviceResolver = aggregatorapiserver.NewEndpointServiceResolver(
			informer.Core().V1().Services().Lister(),
			informer.Core().V1().Endpoints().Lister(),
		)
	} else {
		serviceResolver = aggregatorapiserver.NewClusterIPServiceResolver(
			informer.Core().V1().Services().Lister(),
		)
	}
	// resolve kubernetes.default.svc locally
	if localHost, err := url.Parse(hostname); err == nil {
		serviceResolver = aggregatorapiserver.NewLoopbackServiceResolver(serviceResolver, localHost)
	}
	return serviceResolver
}

func (o *ServerOptions) buildLoopback() (*rest.Config, informers.SharedInformerFactory, error) {
	var loopbackConfig *rest.Config
	var err error
	// TODO(yue9944882): protobuf serialization?
	if len(o.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath) == 0 {
		klog.Infof("loading in-cluster loopback client...")
		loopbackConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, nil, err
		}
	} else {
		klog.Infof("loading out-of-cluster loopback client according to `--kubeconfig` settings...")
		loopbackConfig, err = clientcmd.BuildConfigFromFlags("", o.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath)
		if err != nil {
			return nil, nil, err
		}
	}
	loopbackClient, err := kubernetes.NewForConfig(loopbackConfig)
	if err != nil {
		return nil, nil, err
	}
	kubeInformerFactory := informers.NewSharedInformerFactory(loopbackClient, 0)
	return loopbackConfig, kubeInformerFactory, nil
}

func (o *ServerOptions) RunServer(APIServerVersion *version.Info, stopCh <-chan struct{}, authorizer authorizer.Authorizer, title, version string, tweakConfigFuncs ...func(apiserver *apiserver.Config) error) error {
	aggregatedAPIServerConfig, err := o.Config(tweakConfigFuncs...)
	if err != nil {
		return err
	}
	genericConfig := &aggregatedAPIServerConfig.RecommendedConfig.Config
	genericConfig.Version = APIServerVersion
	genericConfig.Authorization.Authorizer = authorizer
	if o.PrintBearerToken {
		klog.Infof("Serving on loopback...")
		klog.Infof("\n\n********************************\nTo test the server run:\n"+
			"curl -k -H \"Authorization: Bearer %s\" %s\n********************************\n\n",
			genericConfig.LoopbackClientConfig.BearerToken,
			genericConfig.LoopbackClientConfig.Host)
	}

	for _, provider := range o.APIBuilders {
		aggregatedAPIServerConfig.AddApi(provider)
	}

	aggregatedAPIServerConfig.Init()

	genericConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(GetOpenApiDefinition, openapinamer.NewDefinitionNamer(builders.Scheme))
	genericConfig.OpenAPIConfig.Info.Title = title
	genericConfig.OpenAPIConfig.Info.Version = version

	genericServer, err := aggregatedAPIServerConfig.Complete().New()
	if err != nil {
		return err
	}

	for _, h := range o.PostStartHooks {
		if err := genericServer.GenericAPIServer.AddPostStartHook(h.Name, h.Fn); err != nil {
			return err
		}
	}

	s := genericServer.GenericAPIServer.PrepareRun()
	err = OpenAPI.SetSchema(readOpenapi(genericConfig.LoopbackClientConfig.BearerToken, genericServer.GenericAPIServer.Handler))
	if o.PrintOpenapi {
		fmt.Printf("%s", OpenAPI.OpenAPI)
		os.Exit(0)
	}
	if err != nil {
		return err
	}

	if aggregatedAPIServerConfig.InsecureServingInfo != nil {
		fmt.Println("Starting in insecure mode")

		handler := s.GenericAPIServer.UnprotectedHandler()
		handler = genericapifilters.WithAudit(handler, genericConfig.AuditBackend, genericConfig.AuditPolicyChecker, genericConfig.LongRunningFunc)
		handler = genericapifilters.WithAuthentication(handler, server.InsecureSuperuser{}, nil, nil)
		handler = genericfilters.WithCORS(handler, genericConfig.CorsAllowedOriginList, nil, nil, nil, "true")
		handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, genericConfig.LongRunningFunc)
		handler = genericfilters.WithMaxInFlightLimit(handler, genericConfig.MaxRequestsInFlight, genericConfig.MaxMutatingRequestsInFlight, genericConfig.LongRunningFunc)
		infoResolver := server.NewRequestInfoResolver(genericConfig)
		handler = genericapifilters.WithRequestInfo(handler, infoResolver)
		handler = genericfilters.WithPanicRecovery(handler, infoResolver)
		if err := aggregatedAPIServerConfig.InsecureServingInfo.Serve(handler, genericConfig.RequestTimeout, stopCh); err != nil {
			return err
		}
	}

	return s.Run(stopCh)
}

func readOpenapi(bearerToken string, handler *genericapiserver.APIServerHandler) string {
	req, err := http.NewRequest("GET", "/openapi/v2", nil)
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", bearerToken))
	if err != nil {
		panic(fmt.Errorf("Could not create openapi request %v", err))
	}
	resp := &BufferedResponse{}
	handler.ServeHTTP(resp, req)
	return resp.String()
}

type BufferedResponse struct {
	bytes.Buffer
}

func (BufferedResponse) Header() http.Header { return http.Header{} }
func (BufferedResponse) WriteHeader(int)     {}
