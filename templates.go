package main

import (
	"errors"
	"html/template"
	"net/url"
	"path/filepath"
)

var functions = template.FuncMap{
	"urlquery": url.QueryEscape,
	"tagurl":   tagURL,
	"hastag":   hasTag,
}

// templateData holds everything a page might show.
// Add a field here when a page needs new data.
type templateData struct {
}

// newTemplateCache parses every page once at startup. Each page gets its own
// template set (base + partials + that page), so every page can define its own
// "title" and "main" without overwriting the others.
func newTemplateCache() (map[string]*template.Template, error) {
	cache := map[string]*template.Template{}

	pages, err := filepath.Glob("./templates/page/*.html")
	if err != nil {
		return nil, err
	}
	// Glob doesn't fail when nothing matches (e.g. the server was started
	// from the wrong folder), so stop here instead of serving 500s later.
	if len(pages) == 0 {
		return nil, errors.New("no templates found in ./templates/page: run the server from the project folder")
	}

	for _, page := range pages {
		name := filepath.Base(page)

		ts, err := template.New(name).Funcs(functions).ParseFiles("./templates/index.html")

		if err != nil {
			return nil, err
		}

		ts, err = ts.ParseGlob("./templates/partials/*.html")
		if err != nil {
			return nil, err
		}

		ts, err = ts.ParseFiles(page)
		if err != nil {
			return nil, err
		}

		cache[name] = ts
	}
	return cache, nil
}
