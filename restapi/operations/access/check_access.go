// Code generated by go-swagger; DO NOT EDIT.

package access

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// CheckAccessHandlerFunc turns a function with the right signature into a check access handler
type CheckAccessHandlerFunc func(CheckAccessParams) middleware.Responder

// Handle executing the request and returning a response
func (fn CheckAccessHandlerFunc) Handle(params CheckAccessParams) middleware.Responder {
	return fn(params)
}

// CheckAccessHandler interface for that can handle valid check access params
type CheckAccessHandler interface {
	Handle(CheckAccessParams) middleware.Responder
}

// NewCheckAccess creates a new http.Handler for the check access operation
func NewCheckAccess(ctx *middleware.Context, handler CheckAccessHandler) *CheckAccess {
	return &CheckAccess{Context: ctx, Handler: handler}
}

/*
	CheckAccess swagger:route POST /access access checkAccess

CheckAccess check access API
*/
type CheckAccess struct {
	Context *middleware.Context
	Handler CheckAccessHandler
}

func (o *CheckAccess) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewCheckAccessParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
