package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sync"
)

//go:embed multi.tmpl
var multiHTMLTemplate string

// MultiHTML writes a self-contained fleet HTML page: one section per
// cluster with its own per-cluster summary and a results table, plus
// a fleet-wide summary at the top. The page reuses the per-cluster
// Document shape so the per-cluster sections render the same fields a
// single-cluster HTML report would.
//
// The template is parsed once on first use and cached, mirroring the
// single-cluster HTML renderer.
func MultiHTML(w io.Writer, clusters []ClusterReport, opts Options) error {
	tmpl, err := parsedMultiHTMLTemplate()
	if err != nil {
		return err
	}
	doc := buildFleetDocument(clusters, opts)
	if err := tmpl.Execute(w, doc); err != nil {
		return fmt.Errorf("rendering multi-cluster html report: %w", err)
	}
	return nil
}

var (
	multiHTMLTmplCache    *template.Template
	multiHTMLTmplCacheErr error
	multiHTMLTmplCacheDo  sync.Once
)

func parsedMultiHTMLTemplate() (*template.Template, error) {
	multiHTMLTmplCacheDo.Do(func() {
		t, err := template.New("fleet").Funcs(template.FuncMap{
			"displayStatus": displayStatus,
		}).Parse(multiHTMLTemplate)
		if err != nil {
			multiHTMLTmplCacheErr = fmt.Errorf("parsing multi-cluster html template: %w", err)
			return
		}
		multiHTMLTmplCache = t
	})
	return multiHTMLTmplCache, multiHTMLTmplCacheErr
}
