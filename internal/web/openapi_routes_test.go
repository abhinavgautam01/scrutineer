package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type openAPIPath map[string]any

type openAPIDoc struct {
	Paths map[string]openAPIPath `yaml:"paths"`
}

type registeredAPIRoute struct {
	Method string
	Path   string
}

func TestOpenAPICoversRegisteredAPIRoutes(t *testing.T) {
	doc := loadOpenAPIDoc(t)
	var missing []string
	for _, route := range registeredOpenAPIRoutes(t) {
		ops, ok := doc.Paths[route.Path]
		if !ok {
			missing = append(missing, route.Method+" "+route.Path)
			continue
		}
		if _, ok := ops[strings.ToLower(route.Method)]; !ok {
			missing = append(missing, route.Method+" "+route.Path)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("openapi.yaml is missing registered API routes:\n%s", strings.Join(missing, "\n"))
	}
}

func TestOpenAPIRepositoryPatchRequiresFork(t *testing.T) {
	doc := loadOpenAPIDoc(t)
	schema := openAPIRequestSchema(t, doc, "/repositories/{id}", "patch")
	if _, ok := schema["additionalProperties"]; ok {
		t.Fatal("PATCH /repositories/{id} schema should not reject unknown fields; the handler ignores them")
	}
	required, ok := schema["required"].([]any)
	if !ok {
		t.Fatal("PATCH /repositories/{id} schema missing required fields")
	}
	for _, field := range required {
		if field == "fork" {
			return
		}
	}
	t.Fatalf("PATCH /repositories/{id} required fields = %v, want fork", required)
}

func loadOpenAPIDoc(t *testing.T) openAPIDoc {
	t.Helper()
	data, err := os.ReadFile("../../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc openAPIDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func openAPIRequestSchema(t *testing.T, doc openAPIDoc, path, method string) map[string]any {
	t.Helper()
	ops, ok := doc.Paths[path]
	if !ok {
		t.Fatalf("openapi path %s not found", path)
	}
	op := openAPIMap(t, ops[method], path+" "+method)
	requestBody := openAPIMap(t, op["requestBody"], path+" "+method+" requestBody")
	content := openAPIMap(t, requestBody["content"], path+" "+method+" content")
	jsonContent := openAPIMap(t, content["application/json"], path+" "+method+" application/json")
	return openAPIMap(t, jsonContent["schema"], path+" "+method+" schema")
}

func openAPIMap(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	switch m := value.(type) {
	case map[string]any:
		return m
	case openAPIPath:
		return map[string]any(m)
	default:
		t.Fatalf("%s is %T, want map[string]any", label, value)
		return nil
	}
}

func TestRoutesInFunctionRecognizesHandleAndHandleFunc(t *testing.T) {
	src := `package web

func sample(mux interface {
	Handle(string, any)
	HandleFunc(string, any)
}) {
	mux.HandleFunc("GET /repositories", nil)
	mux.Handle("HEAD /repositories", nil)
	mux.HandleFunc("/claim-check", nil)
}
`
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := routesInParsedFile(t, file, "sample.go", "sample", "/v1")
	want := []registeredAPIRoute{
		{Method: "GET", Path: "/v1/repositories"},
		{Method: "HEAD", Path: "/v1/repositories"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %#v, want %#v", got, want)
	}
}

func TestAPIRouteFromPatternRejectsUnsupportedMethod(t *testing.T) {
	for _, pattern := range []string{
		"BREW /coffee",
		"CONNECT /tunnel",
	} {
		if _, _, err := apiRouteFromPattern("", pattern); err == nil {
			t.Fatalf("apiRouteFromPattern accepted unsupported method-qualified pattern %q", pattern)
		}
	}
}

func registeredOpenAPIRoutes(t *testing.T) []registeredAPIRoute {
	t.Helper()
	routes := append(routesInFunction(t, "api.go", "apiHandler", ""), routesInFunction(t, "api_export.go", "exportHandler", "/v1")...)
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return routes
}

func routesInFunction(t *testing.T, filename, funcName, pathPrefix string) []registeredAPIRoute {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return routesInParsedFile(t, file, filename, funcName, pathPrefix)
}

func routesInParsedFile(t *testing.T, file *ast.File, filename, funcName, pathPrefix string) []registeredAPIRoute {
	t.Helper()
	var routes []registeredAPIRoute
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != funcName {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if !isRouteRegistration(call) {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: unquote route pattern: %v", filename, err)
			}
			route, ok, err := apiRouteFromPattern(pathPrefix, pattern)
			if err != nil {
				t.Fatalf("%s: unsupported route pattern %q: %v", filename, pattern, err)
			}
			if ok {
				routes = append(routes, route)
			}
			return true
		})
		return routes
	}
	t.Fatalf("%s: function %s not found", filename, funcName)
	return nil
}

func isRouteRegistration(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Handle" || sel.Sel.Name == "HandleFunc"
}

func apiRouteFromPattern(pathPrefix, pattern string) (registeredAPIRoute, bool, error) {
	fields := strings.Fields(pattern)
	switch len(fields) {
	case 1:
		return registeredAPIRoute{}, false, nil
	case 2:
	default:
		return registeredAPIRoute{}, false, strconv.ErrSyntax
	}
	switch fields[0] {
	case "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE":
		return registeredAPIRoute{Method: fields[0], Path: pathPrefix + fields[1]}, true, nil
	default:
		return registeredAPIRoute{}, false, strconv.ErrSyntax
	}
}
