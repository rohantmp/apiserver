package apiserver

var OpenAPI = OpenAPIValidator{}

type OpenAPIValidator struct {
	OpenAPI string
}

func (o *OpenAPIValidator) SetSchema(openapi string) error {
	var err error
	o.OpenAPI = openapi
	return err
}
