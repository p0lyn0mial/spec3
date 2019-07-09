package spec3_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-openapi/spec"
	"github.com/google/go-cmp/cmp"
	"github.com/p0lyn0mial/spec3"
)

func TestSecuritySchemaJSONSerialization(t *testing.T) {
	cases := []struct {
		name                     string
		securitySchema           *spec3.SecurityScheme
		serializedSecuritySchema string
	}{
		// scenario 1
		{
			name: "scenario1: basic authentication",
			securitySchema: &spec3.SecurityScheme{
				SecuritySchemeProps: spec3.SecuritySchemeProps{
					Type:   "http",
					Scheme: "basic",
				},
			},
			serializedSecuritySchema: `{"type":"http","scheme":"basic"}`,
		},

		// scenario 2
		{
			name: "scenario2: JWT Bearer",
			securitySchema: &spec3.SecurityScheme{
				SecuritySchemeProps: spec3.SecuritySchemeProps{
					Type:         "http",
					Scheme:       "basic",
					BearerFormat: "JWT",
				},
			},
			serializedSecuritySchema: `{"type":"http","scheme":"basic","bearerFormat":"JWT"}`,
		},

		// scenario 3
		{
			name: "scenario3: implicit OAuth2",
			securitySchema: &spec3.SecurityScheme{
				SecuritySchemeProps: spec3.SecuritySchemeProps{
					Type: "oauth2",
					Flows: map[string]*spec3.OAuthFlow{
						"implicit": &spec3.OAuthFlow{
							OAuthFlowProps: spec3.OAuthFlowProps{
								AuthorizationUrl: "https://example.com/api/oauth/dialog",
								Scopes: map[string]string{
									"write:pets": "modify pets in your account",
									"read:pets":  "read your pets",
								},
							},
						},
					},
				},
			},
			serializedSecuritySchema: `{"type":"oauth2","flows":{"implicit":{"authorizationUrl":"https://example.com/api/oauth/dialog","scopes":{"read:pets":"read your pets","write:pets":"modify pets in your account"}}}}`,
		},

		// scenario 4
		{
			name: "scenario4: reference Object",
			securitySchema: &spec3.SecurityScheme{
				Refable: spec.Refable{Ref: spec.MustCreateRef("k8s.io/api/foo/v1beta1b.bar")},
			},
			serializedSecuritySchema: `{"$ref":"k8s.io/api/foo/v1beta1b.bar"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawSecuritySchema, err := json.Marshal(tc.securitySchema)
			if err != nil {
				t.Fatal(err)
			}
			stringSecuritySchema := string(rawSecuritySchema)
			if !cmp.Equal(stringSecuritySchema, tc.serializedSecuritySchema) {
				fmt.Println(stringSecuritySchema)
				t.Fatalf("diff %s", cmp.Diff(stringSecuritySchema, tc.serializedSecuritySchema))
			}
		})
	}
}
