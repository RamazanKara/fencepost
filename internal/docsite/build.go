package docsite

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
)

//go:embed page.html
var page string

//go:embed style.css
var style []byte

type link struct{ Title, URL string }
type document struct {
	Title, Prefix string
	Navigation    []link
	Body          template.HTML
}

func Build(root, output string) error {
	sources := []string{"README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md"}
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			sources = append(sources, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		return err
	}
	t := template.Must(template.New("page").Parse(page))
	markdown := goldmark.New(goldmark.WithExtensions(extension.GFM), goldmark.WithParserOptions(parser.WithAutoHeadingID()))
	navigation := []link{}
	for _, source := range sources {
		data, err := os.ReadFile(filepath.Join(root, source))
		if err != nil {
			return err
		}
		title := strings.TrimPrefix(strings.SplitN(string(data), "\n", 2)[0], "# ")
		navigation = append(navigation, link{strings.TrimSpace(title), outputName(source)})
	}
	for i, source := range sources {
		data, err := os.ReadFile(filepath.Join(root, source))
		if err != nil {
			return err
		}
		node := markdown.Parser().Parse(text.NewReader(data))
		err = ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
			if entering {
				if l, ok := n.(*ast.Link); ok {
					url, anchor, hasAnchor := strings.Cut(string(l.Destination), "#")
					if !strings.Contains(url, ":") && strings.HasSuffix(url, ".md") {
						url = outputName(url)
						if hasAnchor {
							url += "#" + anchor
						}
						l.Destination = []byte(url)
					}
				}
			}
			return ast.WalkContinue, nil
		})
		if err != nil {
			return err
		}
		var body bytes.Buffer
		if err := markdown.Renderer().Render(&body, data, node); err != nil {
			return err
		}
		target := filepath.Join(output, outputName(source))
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		prefix := strings.Repeat("../", strings.Count(source, "/"))
		var result bytes.Buffer
		if err := t.Execute(&result, document{navigation[i].Title, prefix, navigation, template.HTML(body.String())}); err != nil {
			return err
		}
		if err := os.WriteFile(target, result.Bytes(), 0644); err != nil {
			return err
		}
	}
	for _, dir := range []string{"docs/screens", "schema", "examples", "packs"} {
		if _, err := os.Stat(filepath.Join(root, dir)); os.IsNotExist(err) {
			continue
		}
		if err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || strings.HasSuffix(path, ".go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			target := filepath.Join(output, rel)
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			return os.WriteFile(target, data, 0644)
		}); err != nil {
			return err
		}
	}
	license, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "LICENSE"), license, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "style.css"), style, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, ".nojekyll"), nil, 0644); err != nil {
		return err
	}
	fmt.Printf("Built %d documentation pages in %s\n", len(sources), output)
	return nil
}

func outputName(source string) string {
	if filepath.Base(source) == "README.md" {
		return strings.TrimSuffix(source, "README.md") + "index.html"
	}
	return strings.TrimSuffix(source, ".md") + ".html"
}
