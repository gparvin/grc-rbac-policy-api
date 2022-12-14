// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ACL acl
//
// swagger:model acl
type ACL struct {

	// acl
	// Required: true
	ACL []*Item `json:"acl"`

	// name
	// Required: true
	// Min Length: 1
	Name *string `json:"name"`

	// namespace
	// Required: true
	// Min Length: 1
	Namespace *string `json:"namespace"`
}

// Validate validates this acl
func (m *ACL) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateACL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNamespace(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ACL) validateACL(formats strfmt.Registry) error {

	if err := validate.Required("acl", "body", m.ACL); err != nil {
		return err
	}

	for i := 0; i < len(m.ACL); i++ {
		if swag.IsZero(m.ACL[i]) { // not required
			continue
		}

		if m.ACL[i] != nil {
			if err := m.ACL[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("acl" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("acl" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ACL) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	if err := validate.MinLength("name", "body", *m.Name, 1); err != nil {
		return err
	}

	return nil
}

func (m *ACL) validateNamespace(formats strfmt.Registry) error {

	if err := validate.Required("namespace", "body", m.Namespace); err != nil {
		return err
	}

	if err := validate.MinLength("namespace", "body", *m.Namespace, 1); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this acl based on the context it is used
func (m *ACL) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateACL(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ACL) contextValidateACL(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ACL); i++ {

		if m.ACL[i] != nil {
			if err := m.ACL[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("acl" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("acl" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ACL) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ACL) UnmarshalBinary(b []byte) error {
	var res ACL
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
