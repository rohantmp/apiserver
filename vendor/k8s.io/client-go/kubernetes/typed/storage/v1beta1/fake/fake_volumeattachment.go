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

	v1beta1 "k8s.io/api/storage/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	storagev1beta1 "k8s.io/client-go/applyconfigurations/storage/v1beta1"
	testing "k8s.io/client-go/testing"
)

// FakeVolumeAttachments implements VolumeAttachmentInterface
type FakeVolumeAttachments struct {
	Fake *FakeStorageV1beta1
}

var volumeattachmentsResource = v1beta1.SchemeGroupVersion.WithResource("volumeattachments")

var volumeattachmentsKind = v1beta1.SchemeGroupVersion.WithKind("VolumeAttachment")

// Get takes name of the volumeAttachment, and returns the corresponding volumeAttachment object, and an error if there is any.
func (c *FakeVolumeAttachments) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1beta1.VolumeAttachment, err error) {
	emptyResult := &v1beta1.VolumeAttachment{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(volumeattachmentsResource, name), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.VolumeAttachment), err
}

// List takes label and field selectors, and returns the list of VolumeAttachments that match those selectors.
func (c *FakeVolumeAttachments) List(ctx context.Context, opts v1.ListOptions) (result *v1beta1.VolumeAttachmentList, err error) {
	emptyResult := &v1beta1.VolumeAttachmentList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(volumeattachmentsResource, volumeattachmentsKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1beta1.VolumeAttachmentList{ListMeta: obj.(*v1beta1.VolumeAttachmentList).ListMeta}
	for _, item := range obj.(*v1beta1.VolumeAttachmentList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested volumeAttachments.
func (c *FakeVolumeAttachments) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(volumeattachmentsResource, opts))
}

// Create takes the representation of a volumeAttachment and creates it.  Returns the server's representation of the volumeAttachment, and an error, if there is any.
func (c *FakeVolumeAttachments) Create(ctx context.Context, volumeAttachment *v1beta1.VolumeAttachment, opts v1.CreateOptions) (result *v1beta1.VolumeAttachment, err error) {
	emptyResult := &v1beta1.VolumeAttachment{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(volumeattachmentsResource, volumeAttachment), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.VolumeAttachment), err
}

// Update takes the representation of a volumeAttachment and updates it. Returns the server's representation of the volumeAttachment, and an error, if there is any.
func (c *FakeVolumeAttachments) Update(ctx context.Context, volumeAttachment *v1beta1.VolumeAttachment, opts v1.UpdateOptions) (result *v1beta1.VolumeAttachment, err error) {
	emptyResult := &v1beta1.VolumeAttachment{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(volumeattachmentsResource, volumeAttachment), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.VolumeAttachment), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeVolumeAttachments) UpdateStatus(ctx context.Context, volumeAttachment *v1beta1.VolumeAttachment, opts v1.UpdateOptions) (result *v1beta1.VolumeAttachment, err error) {
	emptyResult := &v1beta1.VolumeAttachment{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(volumeattachmentsResource, "status", volumeAttachment), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.VolumeAttachment), err
}

// Delete takes name of the volumeAttachment and deletes it. Returns an error if one occurs.
func (c *FakeVolumeAttachments) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(volumeattachmentsResource, name, opts), &v1beta1.VolumeAttachment{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeVolumeAttachments) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(volumeattachmentsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1beta1.VolumeAttachmentList{})
	return err
}

// Patch applies the patch and returns the patched volumeAttachment.
func (c *FakeVolumeAttachments) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1beta1.VolumeAttachment, err error) {
	emptyResult := &v1beta1.VolumeAttachment{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(volumeattachmentsResource, name, pt, data, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.VolumeAttachment), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied volumeAttachment.
func (c *FakeVolumeAttachments) Apply(ctx context.Context, volumeAttachment *storagev1beta1.VolumeAttachmentApplyConfiguration, opts v1.ApplyOptions) (result *v1beta1.VolumeAttachment, err error) {
	if volumeAttachment == nil {
		return nil, fmt.Errorf("volumeAttachment provided to Apply must not be nil")
	}
	data, err := json.Marshal(volumeAttachment)
	if err != nil {
		return nil, err
	}
	name := volumeAttachment.Name
	if name == nil {
		return nil, fmt.Errorf("volumeAttachment.Name must be provided to Apply")
	}
	emptyResult := &v1beta1.VolumeAttachment{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(volumeattachmentsResource, *name, types.ApplyPatchType, data), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.VolumeAttachment), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeVolumeAttachments) ApplyStatus(ctx context.Context, volumeAttachment *storagev1beta1.VolumeAttachmentApplyConfiguration, opts v1.ApplyOptions) (result *v1beta1.VolumeAttachment, err error) {
	if volumeAttachment == nil {
		return nil, fmt.Errorf("volumeAttachment provided to Apply must not be nil")
	}
	data, err := json.Marshal(volumeAttachment)
	if err != nil {
		return nil, err
	}
	name := volumeAttachment.Name
	if name == nil {
		return nil, fmt.Errorf("volumeAttachment.Name must be provided to Apply")
	}
	emptyResult := &v1beta1.VolumeAttachment{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(volumeattachmentsResource, *name, types.ApplyPatchType, data, "status"), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1beta1.VolumeAttachment), err
}