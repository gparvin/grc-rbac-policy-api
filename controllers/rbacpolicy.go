//  Comapany Api:
//   version: 0.0.1
//   title: Fine Grained RBAC
//  Schemes: http, https
//  Host: localhost:5000
//  BasePath: /
//  Produces:
//    - application/json
//
// securityDefinitions:
//  apiKey:
//    type: apiKey
//    in: header
//    name: authorization
// swagger:meta
package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"open-cluster-management.io/grc-rbac-policy-api/restapi/operations/access"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
)

type ManagedCluster struct {
	// Name of the managed cluster the user has access to
	// in: string
	Name string `json:"name"`
	// Namespace list on the managed cluster the user has access to
	// in: string
	Namespaces []string `json:"namespaces"`
}
type Result struct {
	// ManagedClusters is the list of managed clusters the user can access
	ManagedClusters []ManagedCluster `json:"managedclusters"`
}

type Binding struct {
	// ManagedCluster where a RoleBinding was pushed
	// in: string
	ManagedCluster string `json:"managedcluster"`
	// Namespace on the managed cluster containing the RoleBinding
	// in: string
	Namespace string `json:"namespace"`
	// Role referenced by the RoleBinding
	// in: string
	Role string `json:"role"`
	// User that is given access through the RoleBinding
	// in: string
	User string `json:"user"`
}

var (
	scheme                = runtime.NewScheme()
	setupLog              = ctrl.Log.WithName("setup")
	ControllerName string = "policy-rbac-api"
)

var log = ctrl.Log.WithName(ControllerName)

// swagger:route GET / admin allowed
// AllowedAccess returns true json result if access is allowed
//
// security:
// - apiKey: []
// responses:
//  200: GetCompanies
func AllowedAccess(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Endpoint Hit: allowed")
	user, _, ok := r.BasicAuth()
	if !ok {
		log.Info("No user information found")
	}
	fmt.Printf("got auth info: %s\n", user)
	reqBody, err := json.Marshal(map[string]map[string]string{
		"input": {
			"user":           user,
			"managedcluster": r.Header.Get("managedcluster"),
			"namespace":      r.Header.Get("namespace"),
		},
	})
	if err != nil {
		log.Error(err, "Request header creation failed")
	}
	log.Info("requestheaders", "result", string(reqBody))
	resp, err := http.Post("https://localhost:8181/v1/data/rbac/clusternamespaces/allow",
		"application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Error(err, "request failed")
	} else {
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error(err, "post failed")
		}

		log.Info("body", "result", string(body))
		fmt.Fprintf(w, "%s", body)
	}

}

func CheckAccess(params access.CheckAccessParams) Responder {
	reqBody, err := json.Marshal(map[string]map[string]string{
		"input": {
			"user":           *params.Body.User,
			"managedcluster": *params.Body.Managedcluster,
			"namespace":      params.Body.Namespace,
		},
	})
	if err != nil {
		log.Error(err, "Request header creation failed")
	}
	log.Info("requestheaders", "result", string(reqBody))
	resp, err := http.Post("https://localhost:8181/v1/data/rbac/clusternamespaces/allow",
		"application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Error(err, "request failed")
	} else {
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error(err, "post failed")
		}

		log.Info("body", "result", string(body))
		fmt.Fprintf(w, "%s", body)
	}
}

// swagger:route GET / admin accessList
// ReturnAllAccess returns the entire cache of rbac data
//
// security:
// - apiKey: []
// responses:
//  200: GetCompanies
func ReturnAllAccess(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Endpoint Hit: returnAllAccess")
	content, err := get()
	if err != nil {
		fmt.Println("process content")
	}
	user, _, ok := r.BasicAuth()
	if ok {
		fmt.Printf("got auth info: %s", user)
	}
	results, err := filter(user, content)
	if err != nil {
		log.Error(err, "Failed to filter rbac data")
	} else {
		fmt.Fprintf(w, "%s", results)
	}
}

func filter(user string, content []byte) ([]byte, error) {
	fmt.Printf("Filter: user %s\n", user)
	var rbacResults Result
	var r interface{}
	if err := json.Unmarshal(content, &r); err != nil {
		log.Error(err, "Failed to parse json")
		return json.Marshal(rbacResults)
	}

	results := r.(map[string]interface{})["result"]
	if results == nil {
		log.Info("No results were found")
		return json.Marshal(rbacResults)
	}
	policies := results.(map[string]interface{})

	// TODO: find a better solution for this
	for key, value := range policies {
		fmt.Printf("Found result entry: %s\n", key)
		bindings := value.([]interface{})
		for _, binding := range bindings {
			stuff := binding.(map[string]interface{})

			mcname := stuff["managedcluster"].(string)
			namespace := stuff["namespace"].(string)
			mcuser := stuff["user"].(string)

			if mcuser != user {
				continue
			}
			fmt.Printf("Found binding entry matching user: %s/%s\n", namespace, mcname)
			foundMC := false
			for _, mc := range rbacResults.ManagedClusters {
				foundNS := false
				if mc.Name == mcname {
					for _, ns := range mc.Namespaces {
						if ns == stuff["namespace"] {
							foundNS = true
						}
					}
					if !foundNS {
						mc.Namespaces = append(mc.Namespaces, namespace)
					}
				}
			}
			if !foundMC {
				mymc := ManagedCluster{
					Name:       mcname,
					Namespaces: []string{namespace},
				}
				rbacResults.ManagedClusters = append(rbacResults.ManagedClusters, mymc)
			}
		}
	}

	return json.Marshal(rbacResults)
}

func get() ([]byte, error) {

	resp, err := http.Get("https://localhost:8181/v1/data/acls")
	if err != nil {
		log.Error(err, "get failed")
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err, "get failed")
		return nil, err
	}

	log.Info("body", "resutl", body)
	return body, nil
}
