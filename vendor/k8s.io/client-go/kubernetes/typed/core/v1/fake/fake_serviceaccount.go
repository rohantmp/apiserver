/*
Copyright The Kubernetes Authors.

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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	corev1 "k8s.io/client-go/applyconfigurations/core/v1"
	testing "k8s.io/client-go/testing"
)

// FakeServiceAccounts implements ServiceAccountInterface
type FakeServiceAccounts struct {
	Fake *FakeCoreV1
	ns   string
}

var serviceaccountsResource = v1.SchemeGroupVersion.WithResource("serviceaccounts")

var serviceaccountsKind = v1.SchemeGroupVersion.WithKind("ServiceAccount")

// Get takes name of the serviceAccount, and returns the corresponding serviceAccount object, and an error if there is any.
func (c *FakeServiceAccounts) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.ServiceAccount, err error) {
	emptyResult := &v1.ServiceAccount{}
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(serviceaccountsResource, c.ns, name), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ServiceAccount), err
}

// List takes label and field selectors, and returns the list of ServiceAccounts that match those selectors.
func (c *FakeServiceAccounts) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ServiceAccountList, err error) {
	emptyResult := &v1.ServiceAccountList{}
	obj, err := c.Fake.
		Invokes(testing.NewListAction(serviceaccountsResource, serviceaccountsKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.ServiceAccountList{ListMeta: obj.(*v1.ServiceAccountList).ListMeta}
	for _, item := range obj.(*v1.ServiceAccountList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested serviceAccounts.
func (c *FakeServiceAccounts) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(serviceaccountsResource, c.ns, opts))

}

// Create takes the representation of a serviceAccount and creates it.  Returns the server's representation of the serviceAccount, and an error, if there is any.
func (c *FakeServiceAccounts) Create(ctx context.Context, serviceAccount *v1.ServiceAccount, opts metav1.CreateOptions) (result *v1.ServiceAccount, err error) {
	emptyResult := &v1.ServiceAccount{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(serviceaccountsResource, c.ns, serviceAccount), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ServiceAccount), err
}

// Update takes the representation of a serviceAccount and updates it. Returns the server's representation of the serviceAccount, and an error, if there is any.
func (c *FakeServiceAccounts) Update(ctx context.Context, serviceAccount *v1.ServiceAccount, opts metav1.UpdateOptions) (result *v1.ServiceAccount, err error) {
	emptyResult := &v1.ServiceAccount{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(serviceaccountsResource, c.ns, serviceAccount), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ServiceAccount), err
}

// Delete takes name of the serviceAccount and deletes it. Returns an error if one occurs.
func (c *FakeServiceAccounts) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(serviceaccountsResource, c.ns, name, opts), &v1.ServiceAccount{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeServiceAccounts) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(serviceaccountsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.ServiceAccountList{})
	return err
}

// Patch applies the patch and returns the patched serviceAccount.
func (c *FakeServiceAccounts) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ServiceAccount, err error) {
	emptyResult := &v1.ServiceAccount{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(serviceaccountsResource, c.ns, name, pt, data, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ServiceAccount), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied serviceAccount.
func (c *FakeServiceAccounts) Apply(ctx context.Context, serviceAccount *corev1.ServiceAccountApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ServiceAccount, err error) {
	if serviceAccount == nil {
		return nil, fmt.Errorf("serviceAccount provided to Apply must not be nil")
	}
	data, err := json.Marshal(serviceAccount)
	if err != nil {
		return nil, err
	}
	name := serviceAccount.Name
	if name == nil {
		return nil, fmt.Errorf("serviceAccount.Name must be provided to Apply")
	}
	emptyResult := &v1.ServiceAccount{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(serviceaccountsResource, c.ns, *name, types.ApplyPatchType, data), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1.ServiceAccount), err
}

// CreateToken takes the representation of a tokenRequest and creates it.  Returns the server's representation of the tokenRequest, and an error, if there is any.
func (c *FakeServiceAccounts) CreateToken(ctx context.Context, serviceAccountName string, tokenRequest *authenticationv1.TokenRequest, opts metav1.CreateOptions) (result *authenticationv1.TokenRequest, err error) {
	emptyResult := &authenticationv1.TokenRequest{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateSubresourceAction(serviceaccountsResource, serviceAccountName, "token", c.ns, tokenRequest), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*authenticationv1.TokenRequest), err
}