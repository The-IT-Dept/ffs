package apiserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// Problem is an error that is answered as an RFC 9457 problem document. Handlers return it, or a
// store error problemOf maps.
type Problem struct {
	Status int
	Code   apigen.ProblemCode
	Detail string
}

func (p *Problem) Error() string {
	if p.Detail == "" {
		return fmt.Sprintf("%d %s", p.Status, p.Code)
	}
	return fmt.Sprintf("%d %s: %s", p.Status, p.Code, p.Detail)
}

// problemOf maps err to the problem it is answered with: a *Problem is itself, a store cursor that
// belongs to another query is 400 invalid_cursor, and a scope the query or the parser rejects is
// 400 invalid_scope. Anything else is nil, which the caller answers as 500 internal.
func problemOf(err error) *Problem {
	var p *Problem
	switch {
	case err == nil:
		return nil
	case errors.As(err, &p):
		return p
	case errors.Is(err, store.ErrBadCursor):
		return &Problem{Status: http.StatusBadRequest, Code: apigen.ProblemCodeInvalidCursor}
	case errors.Is(err, store.ErrScope), errors.Is(err, model.ErrBadScope):
		return &Problem{Status: http.StatusBadRequest, Code: apigen.ProblemCodeInvalidScope,
			Detail: "scope: not supported by this operation"}
	}
	return nil
}

// badParam is a 400 invalid_parameter problem naming the parameter.
func badParam(name, detail string) *Problem {
	return &Problem{Status: http.StatusBadRequest, Code: apigen.ProblemCodeInvalidParameter, Detail: name + ": " + detail}
}

// notFound is a 404 not_found problem.
func notFound(detail string) *Problem {
	return &Problem{Status: http.StatusNotFound, Code: apigen.ProblemCodeNotFound, Detail: detail}
}

// bindProblem is the 400 invalid_parameter problem of a parameter the generated router could not
// bind, naming the parameter when the error does.
func bindProblem(err error) *Problem {
	var (
		required *apigen.RequiredParamError
		format   *apigen.InvalidParamFormatError
		tooMany  *apigen.TooManyValuesForParamError
		header   *apigen.RequiredHeaderError
	)
	switch {
	case errors.As(err, &required):
		return badParam(required.ParamName, "required")
	case errors.As(err, &format):
		return badParam(format.ParamName, "invalid format: "+format.Err.Error())
	case errors.As(err, &tooMany):
		return badParam(tooMany.ParamName, fmt.Sprintf("expected one value, got %d", tooMany.Count))
	case errors.As(err, &header):
		return badParam(header.ParamName, "required")
	}
	return &Problem{Status: http.StatusBadRequest, Code: apigen.ProblemCodeInvalidParameter, Detail: err.Error()}
}

// writeProblem answers p as application/problem+json, stamped with the cluster and the time. A nil
// p is 500 internal.
func writeProblem(w http.ResponseWriter, r *http.Request, p *Problem, cluster string, at time.Time) {
	if p == nil {
		p = &Problem{Status: http.StatusInternalServerError, Code: apigen.ProblemCodeInternal, Detail: "internal error"}
	}
	doc := apigen.Problem{
		Cluster: cluster, GeneratedAt: at.UTC(), Type: "about:blank", Title: http.StatusText(p.Status), Status: p.Status,
		Detail: optString(p.Detail), Instance: optString(r.URL.Path), Code: p.Code,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_, _ = w.Write(body)
}
