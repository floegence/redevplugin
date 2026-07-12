package pluginpkg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"path"
	"strings"
	"unicode/utf8"

	parse "github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
	"github.com/tdewolff/parse/v2/js"
	"golang.org/x/net/html"
)

const OpaqueSurfaceDocumentSchemaVersion = "redevplugin.opaque_surface_document.v1"

type OpaqueSurfaceWorkerType string

const OpaqueSurfaceWorkerClassic OpaqueSurfaceWorkerType = "classic"

const opaqueSurfaceWorkerScriptType = "text/redevplugin-worker"

const (
	maxOpaqueSurfaceBodyBytes     = 4 << 20
	maxOpaqueSurfaceStyleBytes    = 2 << 20
	maxOpaqueSurfaceWorkerBytes   = 4 << 20
	maxOpaqueSurfaceCriticalBytes = 8 << 20
	maxOpaqueSurfaceLazyAssets    = 128
	maxOpaqueSurfaceLazyBytes     = 32 << 20
)

type OpaqueSurfaceDocument struct {
	SchemaVersion string               `json:"schema_version"`
	EntryPath     string               `json:"entry_path"`
	EntrySHA256   string               `json:"entry_sha256"`
	Title         string               `json:"title,omitempty"`
	Language      string               `json:"language,omitempty"`
	Direction     string               `json:"direction,omitempty"`
	BodyHTML      string               `json:"body_html"`
	Styles        []OpaqueSurfaceStyle `json:"styles"`
	Worker        OpaqueSurfaceWorker  `json:"worker"`
	Assets        []OpaqueSurfaceAsset `json:"assets"`
	CriticalBytes int64                `json:"critical_bytes"`
}

type OpaqueSurfaceStyle struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}

type OpaqueSurfaceWorker struct {
	Path    string                  `json:"path"`
	SHA256  string                  `json:"sha256"`
	Type    OpaqueSurfaceWorkerType `json:"type"`
	Content string                  `json:"content"`
}

type OpaqueSurfaceAsset struct {
	BindingID   string `json:"binding_id"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
}

type OpaqueSurfaceAssetReader func(assetPath string) (Asset, error)

type opaqueSurfaceBuilder struct {
	entryPath string
	readAsset OpaqueSurfaceAssetReader
	document  OpaqueSurfaceDocument
	assets    map[string]OpaqueSurfaceAsset
	lazyBytes int64
	workerSet bool
}

func BuildOpaqueSurfaceDocument(entryPath string, readAsset OpaqueSurfaceAssetReader) (OpaqueSurfaceDocument, error) {
	entryPath, err := validatePackageAssetPath(entryPath)
	if err != nil {
		return OpaqueSurfaceDocument{}, err
	}
	if readAsset == nil {
		return OpaqueSurfaceDocument{}, errors.New("opaque surface asset reader is required")
	}
	entry, err := readOpaqueSurfaceAsset(readAsset, entryPath)
	if err != nil {
		return OpaqueSurfaceDocument{}, err
	}
	if !isHTMLAsset(entryPath) || !utf8.Valid(entry.Content) {
		return OpaqueSurfaceDocument{}, fmt.Errorf("opaque surface entry %q must be UTF-8 HTML", entryPath)
	}
	doc, err := html.Parse(bytes.NewReader(entry.Content))
	if err != nil {
		return OpaqueSurfaceDocument{}, fmt.Errorf("opaque surface entry %q: %w", entryPath, err)
	}
	builder := &opaqueSurfaceBuilder{
		entryPath: entryPath,
		readAsset: readAsset,
		document: OpaqueSurfaceDocument{
			SchemaVersion: OpaqueSurfaceDocumentSchemaVersion,
			EntryPath:     entryPath,
			EntrySHA256:   entry.Entry.SHA256,
			Styles:        []OpaqueSurfaceStyle{},
			Assets:        []OpaqueSurfaceAsset{},
			CriticalBytes: int64(len(entry.Content)),
		},
		assets: map[string]OpaqueSurfaceAsset{},
	}
	body, err := builder.sanitizeDocument(doc)
	if err != nil {
		return OpaqueSurfaceDocument{}, err
	}
	if !builder.workerSet {
		return OpaqueSurfaceDocument{}, errors.New("opaque surface entry must declare exactly one bundled worker script")
	}
	if err := validateOpaqueSurfaceBody(body); err != nil {
		return OpaqueSurfaceDocument{}, fmt.Errorf("opaque surface entry %q: %w", entryPath, err)
	}
	var rendered strings.Builder
	for child := body.FirstChild; child != nil; child = child.NextSibling {
		if err := html.Render(&rendered, child); err != nil {
			return OpaqueSurfaceDocument{}, fmt.Errorf("render opaque surface body: %w", err)
		}
	}
	builder.document.BodyHTML = rendered.String()
	if len(builder.document.BodyHTML) > maxOpaqueSurfaceBodyBytes {
		return OpaqueSurfaceDocument{}, fmt.Errorf("opaque surface body exceeds %d bytes", maxOpaqueSurfaceBodyBytes)
	}
	if builder.document.CriticalBytes > maxOpaqueSurfaceCriticalBytes {
		return OpaqueSurfaceDocument{}, fmt.Errorf("opaque surface critical assets exceed %d bytes", maxOpaqueSurfaceCriticalBytes)
	}
	return builder.document, nil
}

func (b *opaqueSurfaceBuilder) sanitizeDocument(doc *html.Node) (*html.Node, error) {
	baseDir := path.Dir(b.entryPath)
	if baseDir == "." {
		baseDir = ""
	}
	var body *html.Node
	var walk func(*html.Node) error
	walk = func(node *html.Node) error {
		if node.Type == html.CommentNode {
			removeHTMLNode(node)
			return nil
		}
		if node.Type == html.ElementNode {
			tag := strings.ToLower(node.Data)
			switch tag {
			case "html":
				language := strings.TrimSpace(htmlAttribute(node, "lang"))
				if len(language) > 64 {
					return fmt.Errorf("opaque surface entry %q language exceeds 64 bytes", b.entryPath)
				}
				direction := strings.ToLower(strings.TrimSpace(htmlAttribute(node, "dir")))
				if direction != "" && direction != "ltr" && direction != "rtl" && direction != "auto" {
					return fmt.Errorf("opaque surface entry %q direction %q is not supported", b.entryPath, direction)
				}
				b.document.Language = language
				b.document.Direction = direction
			case "head":
			case "body":
				body = node
			case "title":
				title := strings.TrimSpace(nodeTextContent(node))
				if len(title) > 256 {
					return fmt.Errorf("opaque surface entry %q title exceeds 256 bytes", b.entryPath)
				}
				b.document.Title = title
			case "base", "iframe", "frame", "object", "embed", "portal":
				return fmt.Errorf("opaque surface entry %q contains an embedded browsing context or base URL", b.entryPath)
			case "script":
				if err := b.setWorker(node, baseDir); err != nil {
					return err
				}
				removeHTMLNode(node)
				return nil
			case "link":
				rel := strings.ToLower(strings.TrimSpace(htmlAttribute(node, "rel")))
				if rel != "stylesheet" {
					return fmt.Errorf("opaque surface entry %q contains unsupported link rel %q", b.entryPath, rel)
				}
				if err := b.appendStyle(node, baseDir); err != nil {
					return err
				}
				removeHTMLNode(node)
				return nil
			case "style":
				return fmt.Errorf("opaque surface entry %q inline style block is not allowed; use an external stylesheet", b.entryPath)
			case "meta":
				if strings.EqualFold(strings.TrimSpace(htmlAttribute(node, "http-equiv")), "refresh") {
					return fmt.Errorf("opaque surface entry %q meta refresh is not allowed", b.entryPath)
				}
			default:
				if _, ok := opaqueSurfaceAllowedTags[tag]; !ok {
					return fmt.Errorf("opaque surface element <%s> is not supported", tag)
				}
			}
			if _, ok := opaqueSurfaceAllowedTags[tag]; ok {
				if err := b.sanitizeAttributes(node, tag, baseDir); err != nil {
					return err
				}
			}
		}
		for child := node.FirstChild; child != nil; {
			next := child.NextSibling
			if err := walk(child); err != nil {
				return err
			}
			child = next
		}
		return nil
	}
	if err := walk(doc); err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("opaque surface entry %q has no body", b.entryPath)
	}
	return body, nil
}

func (b *opaqueSurfaceBuilder) setWorker(node *html.Node, baseDir string) error {
	if b.workerSet {
		return errors.New("opaque surface entry must declare exactly one bundled worker script")
	}
	if strings.TrimSpace(nodeTextContent(node)) != "" {
		return errors.New("opaque surface scripts must be an external bundled worker script")
	}
	if strings.ToLower(strings.TrimSpace(htmlAttribute(node, "type"))) != opaqueSurfaceWorkerScriptType {
		return fmt.Errorf("opaque surface worker must declare type=%s", opaqueSurfaceWorkerScriptType)
	}
	assetPath, err := resolveOpaqueSurfaceAssetPath(baseDir, htmlAttribute(node, "src"))
	if err != nil {
		return fmt.Errorf("opaque surface worker: %w", err)
	}
	asset, err := readOpaqueSurfaceAsset(b.readAsset, assetPath)
	if err != nil {
		return err
	}
	if !isScriptAsset(assetPath) || !utf8.Valid(asset.Content) {
		return fmt.Errorf("opaque surface worker %q must be UTF-8 JavaScript", assetPath)
	}
	if len(asset.Content) > maxOpaqueSurfaceWorkerBytes {
		return fmt.Errorf("opaque surface worker %q exceeds %d bytes", assetPath, maxOpaqueSurfaceWorkerBytes)
	}
	if err := validateBundledWorkerJavaScript(assetPath, asset.Content); err != nil {
		return err
	}
	b.document.Worker = OpaqueSurfaceWorker{
		Path:    assetPath,
		SHA256:  asset.Entry.SHA256,
		Type:    OpaqueSurfaceWorkerClassic,
		Content: string(asset.Content),
	}
	b.document.CriticalBytes += int64(len(asset.Content))
	b.workerSet = true
	return nil
}

func (b *opaqueSurfaceBuilder) appendStyle(node *html.Node, htmlBaseDir string) error {
	assetPath, err := resolveOpaqueSurfaceAssetPath(htmlBaseDir, htmlAttribute(node, "href"))
	if err != nil {
		return fmt.Errorf("opaque surface stylesheet: %w", err)
	}
	asset, err := readOpaqueSurfaceAsset(b.readAsset, assetPath)
	if err != nil {
		return err
	}
	if strings.ToLower(path.Ext(assetPath)) != ".css" || !utf8.Valid(asset.Content) {
		return fmt.Errorf("opaque surface stylesheet %q must be UTF-8 CSS", assetPath)
	}
	content, err := b.rewriteStyle(assetPath, asset.Content)
	if err != nil {
		return err
	}
	if len(content) > maxOpaqueSurfaceStyleBytes {
		return fmt.Errorf("opaque surface stylesheet %q exceeds %d bytes", assetPath, maxOpaqueSurfaceStyleBytes)
	}
	b.document.Styles = append(b.document.Styles, OpaqueSurfaceStyle{Path: assetPath, SHA256: asset.Entry.SHA256, Content: content})
	b.document.CriticalBytes += int64(len(content))
	return nil
}

func (b *opaqueSurfaceBuilder) sanitizeAttributes(node *html.Node, tag string, baseDir string) error {
	attrs := make([]html.Attribute, 0, len(node.Attr)+2)
	for _, attr := range node.Attr {
		key := strings.ToLower(attr.Key)
		if attr.Namespace != "" {
			return fmt.Errorf("opaque surface element <%s> attribute %q is not supported", tag, attr.Key)
		}
		if strings.HasPrefix(key, "on") {
			return fmt.Errorf("opaque surface element <%s> inline event handler %q is not allowed", tag, attr.Key)
		}
		if key == "style" {
			return fmt.Errorf("opaque surface element <%s> inline style attribute is not allowed", tag)
		}
		if key == "srcdoc" {
			return fmt.Errorf("opaque surface element <%s> srcdoc is not allowed", tag)
		}
		if key == "data-redevplugin-asset-binding" || key == "data-redevplugin-asset-attr" {
			return fmt.Errorf("opaque surface element <%s> uses reserved asset binding attribute %q", tag, attr.Key)
		}
		if key == "srcset" {
			return fmt.Errorf("opaque surface element <%s> srcset is not supported", tag)
		}
		if tag == "input" && key == "type" && !safeOpaqueInputType(attr.Val) {
			return fmt.Errorf("opaque surface input type %q is not supported", attr.Val)
		}
		if tag == "input" && key == "type" {
			attr.Val = canonicalOpaqueInputType(attr.Val)
		}
		if !isHTMLURLAttribute(tag, key) {
			if err := validateOpaqueSurfaceAttribute(tag, key, attr.Val); err != nil {
				return err
			}
			attr.Key = key
			attrs = append(attrs, attr)
			continue
		}
		if !opaqueSurfaceMediaURL(tag, key) {
			return fmt.Errorf("opaque surface element <%s> URL attribute %q is not supported", tag, attr.Key)
		}
		assetPath, err := resolveOpaqueSurfaceAssetPath(baseDir, attr.Val)
		if err != nil {
			return err
		}
		asset, err := readOpaqueSurfaceAsset(b.readAsset, assetPath)
		if err != nil {
			return err
		}
		binding, err := b.registerAsset(asset)
		if err != nil {
			return err
		}
		attrs = append(attrs,
			html.Attribute{Key: "data-redevplugin-asset-binding", Val: binding.BindingID},
			html.Attribute{Key: "data-redevplugin-asset-attr", Val: key},
		)
	}
	if len(attrs) > opaqueSurfaceMaxAttributesPerElement {
		return fmt.Errorf("opaque surface element <%s> exceeds %d attributes", tag, opaqueSurfaceMaxAttributesPerElement)
	}
	node.Attr = attrs
	return nil
}

func (b *opaqueSurfaceBuilder) rewriteStyle(assetPath string, content []byte) (string, error) {
	parser := css.NewParser(parse.NewInput(bytes.NewReader(content)), false)
	for {
		grammar, _, data := parser.Next()
		if grammar == css.ErrorGrammar {
			if err := parser.Err(); err != nil && !errors.Is(err, io.EOF) {
				return "", fmt.Errorf("opaque surface stylesheet %q: %w", assetPath, err)
			}
			break
		}
		if (grammar == css.AtRuleGrammar || grammar == css.BeginAtRuleGrammar) && strings.EqualFold(strings.TrimPrefix(string(data), "@"), "import") {
			return "", fmt.Errorf("opaque surface stylesheet %q cannot use @import", assetPath)
		}
	}
	baseDir := path.Dir(assetPath)
	if baseDir == "." {
		baseDir = ""
	}
	lexer := css.NewLexer(parse.NewInput(bytes.NewReader(content)))
	var out strings.Builder
	for {
		tokenType, data := lexer.Next()
		if tokenType == css.ErrorToken {
			if err := lexer.Err(); err != nil && !errors.Is(err, io.EOF) {
				return "", fmt.Errorf("opaque surface stylesheet %q: %w", assetPath, err)
			}
			break
		}
		if tokenType == css.BadURLToken || tokenType == css.BadStringToken {
			return "", fmt.Errorf("opaque surface stylesheet %q contains an invalid URL or string", assetPath)
		}
		if tokenType == css.AtKeywordToken && strings.EqualFold(strings.TrimPrefix(string(data), "@"), "import") {
			return "", fmt.Errorf("opaque surface stylesheet %q cannot use @import", assetPath)
		}
		if tokenType != css.URLToken {
			out.Write(data)
			continue
		}
		rawURL, err := canonicalCSSURL(data)
		if err != nil {
			return "", fmt.Errorf("opaque surface stylesheet %q: %w", assetPath, err)
		}
		resolved, err := resolveOpaqueSurfaceAssetPath(baseDir, rawURL)
		if err != nil {
			return "", fmt.Errorf("opaque surface stylesheet %q URL must be package-local: %w", assetPath, err)
		}
		asset, err := readOpaqueSurfaceAsset(b.readAsset, resolved)
		if err != nil {
			return "", err
		}
		binding, err := b.registerAsset(asset)
		if err != nil {
			return "", err
		}
		out.WriteString("var(--redevplugin-asset-")
		out.WriteString(binding.BindingID)
		out.WriteByte(')')
	}
	return out.String(), nil
}

func (b *opaqueSurfaceBuilder) registerAsset(asset Asset) (OpaqueSurfaceAsset, error) {
	if existing, ok := b.assets[asset.Entry.Path]; ok {
		return existing, nil
	}
	if len(b.document.Assets) >= maxOpaqueSurfaceLazyAssets {
		return OpaqueSurfaceAsset{}, fmt.Errorf("opaque surface lazy asset count exceeds %d", maxOpaqueSurfaceLazyAssets)
	}
	assetSize := int64(len(asset.Content))
	if assetSize > maxOpaqueSurfaceLazyBytes-b.lazyBytes {
		return OpaqueSurfaceAsset{}, fmt.Errorf("opaque surface lazy asset bytes exceed %d", maxOpaqueSurfaceLazyBytes)
	}
	contentType := strings.TrimSpace(asset.Entry.ContentType)
	if contentType == "" {
		contentType = mime.TypeByExtension(strings.ToLower(path.Ext(asset.Entry.Path)))
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if len(contentType) > 256 {
		return OpaqueSurfaceAsset{}, fmt.Errorf("opaque surface asset %q content type exceeds 256 bytes", asset.Entry.Path)
	}
	binding := OpaqueSurfaceAsset{
		BindingID:   "asset_" + strings.TrimPrefix(sha256String([]byte(asset.Entry.Path)), "sha256:")[:24],
		Path:        asset.Entry.Path,
		SHA256:      asset.Entry.SHA256,
		Size:        assetSize,
		ContentType: contentType,
	}
	b.assets[asset.Entry.Path] = binding
	b.document.Assets = append(b.document.Assets, binding)
	b.lazyBytes += assetSize
	return binding, nil
}

func validateBundledWorkerJavaScript(assetPath string, content []byte) error {
	lexer := js.NewLexer(parse.NewInput(bytes.NewReader(content)))
	for {
		tokenType, _ := lexer.Next()
		if tokenType == js.ErrorToken {
			if err := lexer.Err(); err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("opaque surface worker %q: %w", assetPath, err)
			}
			break
		}
		if tokenType == js.ImportToken || tokenType == js.ExportToken {
			return fmt.Errorf("opaque surface worker %q imports and exports are not allowed; bundle the worker into one classic script", assetPath)
		}
		if tokenType == js.WithToken {
			return fmt.Errorf("opaque surface worker %q is invalid JavaScript: with statements are unavailable in the strict worker wrapper", assetPath)
		}
	}
	if _, err := js.Parse(parse.NewInput(bytes.NewReader(content)), js.Options{}); err != nil {
		return fmt.Errorf("opaque surface worker %q is invalid JavaScript: %w", assetPath, err)
	}
	wrapped := make([]byte, 0, len(content)+64)
	wrapped = append(wrapped, "const __redevpluginPluginMain = () => {\n\"use strict\";\n"...)
	wrapped = append(wrapped, content...)
	wrapped = append(wrapped, "\n};\n"...)
	if _, err := js.Parse(parse.NewInput(bytes.NewReader(wrapped)), js.Options{}); err != nil {
		return fmt.Errorf("opaque surface worker %q is invalid JavaScript: %w", assetPath, err)
	}
	return nil
}

func canonicalCSSURL(token []byte) (string, error) {
	value := strings.TrimSpace(string(token))
	if len(value) < 5 || !strings.EqualFold(value[:4], "url(") || value[len(value)-1] != ')' {
		return "", errors.New("CSS URL token is invalid")
	}
	value = strings.TrimSpace(value[4 : len(value)-1])
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		value = value[1 : len(value)-1]
	}
	if value == "" || strings.ContainsAny(value, "\\\r\n\t\x00") || strings.Contains(value, ":") || strings.HasPrefix(value, "//") || strings.HasPrefix(value, "#") {
		return "", errors.New("CSS URL must be a canonical package-local path")
	}
	return value, nil
}

func validateOpaqueSurfaceBody(body *html.Node) error {
	nodes := 0
	var walk func(*html.Node, int) error
	walk = func(node *html.Node, depth int) error {
		nodes++
		if nodes > opaqueSurfaceMaxRenderNodes {
			return fmt.Errorf("body exceeds %d render nodes", opaqueSurfaceMaxRenderNodes)
		}
		if depth > opaqueSurfaceMaxRenderDepth {
			return fmt.Errorf("body exceeds render depth %d", opaqueSurfaceMaxRenderDepth)
		}
		switch node.Type {
		case html.TextNode:
			if len(node.Data) > opaqueSurfaceMaxTextLength {
				return fmt.Errorf("body text node exceeds %d bytes", opaqueSurfaceMaxTextLength)
			}
			return nil
		case html.ElementNode:
			tag := strings.ToLower(node.Data)
			if _, ok := opaqueSurfaceAllowedTags[tag]; !ok {
				return fmt.Errorf("element <%s> is not supported", tag)
			}
			if len(node.Attr) > opaqueSurfaceMaxAttributesPerElement {
				return fmt.Errorf("element <%s> exceeds %d attributes", tag, opaqueSurfaceMaxAttributesPerElement)
			}
			seen := make(map[string]struct{}, len(node.Attr))
			for _, attr := range node.Attr {
				if attr.Namespace != "" {
					return fmt.Errorf("element <%s> attribute %q is not supported", tag, attr.Key)
				}
				key := strings.ToLower(attr.Key)
				if _, ok := seen[key]; ok {
					return fmt.Errorf("element <%s> repeats attribute %q", tag, key)
				}
				seen[key] = struct{}{}
				if err := validateOpaqueSurfaceAttribute(tag, key, attr.Val); err != nil {
					return err
				}
			}
		default:
			return errors.New("body contains a non-renderable node")
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for child := body.FirstChild; child != nil; child = child.NextSibling {
		if err := walk(child, 1); err != nil {
			return err
		}
	}
	return nil
}

func validateOpaqueSurfaceAttribute(tag string, key string, value string) error {
	key = strings.ToLower(key)
	if len(value) > opaqueSurfaceMaxAttributeValueLength {
		return fmt.Errorf("opaque surface element <%s> attribute %q exceeds %d bytes", tag, key, opaqueSurfaceMaxAttributeValueLength)
	}
	if strings.HasPrefix(key, "on") || key == "style" || key == "src" || key == "srcset" || key == "href" || key == "srcdoc" || key == "action" || key == "formaction" || key == "poster" {
		return fmt.Errorf("opaque surface element <%s> attribute %q is not supported", tag, key)
	}
	_, global := opaqueSurfaceGlobalAttributes[key]
	_, tagSpecific := opaqueSurfaceTagAttributes[tag][key]
	if !global && !tagSpecific && !strings.HasPrefix(key, "aria-") {
		return fmt.Errorf("opaque surface element <%s> attribute %q is not supported", tag, key)
	}
	if key == "data-redevplugin-action" && !validOpaqueSurfaceIdentifier(value) {
		return fmt.Errorf("opaque surface element <%s> action identifier %q is invalid", tag, value)
	}
	if key == "data-redevplugin-asset-binding" && !validOpaqueSurfaceHandle(value, "asset") {
		return fmt.Errorf("opaque surface element <%s> asset binding %q is invalid", tag, value)
	}
	if key == "data-redevplugin-asset-attr" && value != "src" && value != "poster" {
		return fmt.Errorf("opaque surface element <%s> asset attribute %q is invalid", tag, value)
	}
	if tag == "input" && key == "type" && !safeOpaqueInputType(value) {
		return fmt.Errorf("opaque surface input type %q is not supported", value)
	}
	return nil
}

func validOpaqueSurfaceIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._:-", char) {
			continue
		}
		return false
	}
	return true
}

func validOpaqueSurfaceHandle(value string, prefix string) bool {
	if !strings.HasPrefix(value, prefix+"_") || len(value) < 8 || len(value) > 160 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func safeOpaqueInputType(value string) bool {
	value = canonicalOpaqueInputType(value)
	_, ok := opaqueSurfaceSafeInputTypes[value]
	return ok
}

func canonicalOpaqueInputType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "text"
	}
	return value
}

func opaqueSurfaceMediaURL(tag string, attr string) bool {
	switch tag {
	case "img", "source", "track":
		return attr == "src"
	case "audio", "video":
		return attr == "src" || attr == "poster"
	case "input":
		return attr == "src"
	default:
		return false
	}
}

func resolveOpaqueSurfaceAssetPath(baseDir string, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("package-local asset path is required")
	}
	return resolvePackageRelativeAssetPath(baseDir, raw)
}

func readOpaqueSurfaceAsset(readAsset OpaqueSurfaceAssetReader, assetPath string) (Asset, error) {
	asset, err := readAsset(assetPath)
	if err != nil {
		return Asset{}, fmt.Errorf("read opaque surface asset %q: %w", assetPath, err)
	}
	if asset.Entry.Path != assetPath || asset.Entry.SHA256 == "" {
		return Asset{}, fmt.Errorf("opaque surface asset %q metadata is invalid", assetPath)
	}
	actualSHA256 := sha256String(asset.Content)
	if asset.Entry.SHA256 != actualSHA256 {
		return Asset{}, fmt.Errorf("opaque surface asset %q sha256 metadata mismatch: got %s want %s", assetPath, asset.Entry.SHA256, actualSHA256)
	}
	if asset.Entry.Size != 0 && asset.Entry.Size != int64(len(asset.Content)) {
		return Asset{}, fmt.Errorf("opaque surface asset %q size metadata mismatch", assetPath)
	}
	return asset, nil
}

func htmlAttribute(node *html.Node, name string) string {
	for _, attr := range node.Attr {
		if strings.EqualFold(attr.Key, name) {
			return attr.Val
		}
	}
	return ""
}

func removeHTMLNode(node *html.Node) {
	if node.Parent != nil {
		node.Parent.RemoveChild(node)
	}
}
