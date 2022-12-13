// Code generated by go generate; DO NOT EDIT.
package containers

import (
	"net/url"

	"github.com/containers/podman/v4/pkg/bindings/internal/util"
)

// Changed returns true if named field has been set
func (o *DiffOptions) Changed(fieldName string) bool {
	return util.Changed(o, fieldName)
}

// ToParams formats struct fields to be passed to API service
func (o *DiffOptions) ToParams() (url.Values, error) {
	return util.ToParams(o)
}

// WithParent set field Parent to given value
func (o *DiffOptions) WithParent(value string) *DiffOptions {
	o.Parent = &value
	return o
}

// GetParent returns value of field Parent
func (o *DiffOptions) GetParent() string {
	if o.Parent == nil {
		var z string
		return z
	}
	return *o.Parent
}

// WithDiffType set field DiffType to given value
func (o *DiffOptions) WithDiffType(value string) *DiffOptions {
	o.DiffType = &value
	return o
}

// GetDiffType returns value of field DiffType
func (o *DiffOptions) GetDiffType() string {
	if o.DiffType == nil {
		var z string
		return z
	}
	return *o.DiffType
}
