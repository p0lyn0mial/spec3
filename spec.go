package spec3

// OpenAPI is an object that describes an API and conforms to the OpenAPI Specification.
//
// Note: at the moment this struct doesn't fully conforms to the OpenAPI Specification in version 3.0,
//       it is just a proof of concept
type OpenAPI struct {
	Components Components `json:"components,omitempty"`
}