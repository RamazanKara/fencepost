package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/RamazanKara/fencepost/internal/clientconfig"
	"github.com/RamazanKara/fencepost/internal/version"
)

type Tool map[string]json.RawMessage

func (t Tool) Text(key string) string {
	var value string
	_ = json.Unmarshal(t[key], &value)
	return value
}

type Catalog struct {
	Tools        []Tool
	Prompts      []json.RawMessage
	Resources    []json.RawMessage
	Instructions string
}

type Client struct {
	stdio        *stdio
	http         *httpTransport
	version      string
	capabilities map[string]json.RawMessage
	instructions string
	next         atomic.Int64
}

func Connect(ctx context.Context, server clientconfig.Server) (*Client, error) {
	s, err := clientconfig.Resolve(server, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	c := &Client{version: Latest}
	switch s.Transport {
	case "stdio":
		c.stdio, err = startStdio(ctx, s)
	case "http":
		c.http, err = newHTTP(s.URL, s.Headers)
	default:
		return nil, errors.New("unsupported transport; use stdio or Streamable HTTP")
	}
	if err != nil {
		return nil, err
	}
	if err = c.negotiate(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) Call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	copyParams := make(map[string]any, len(params)+1)
	for k, v := range params {
		copyParams[k] = v
	}
	if c.version == Latest {
		meta := map[string]any{}
		if original, ok := params["_meta"].(map[string]any); ok {
			for k, v := range original {
				meta[k] = v
			}
		}
		meta["io.modelcontextprotocol/protocolVersion"] = Latest
		meta["io.modelcontextprotocol/clientCapabilities"] = map[string]any{}
		meta["io.modelcontextprotocol/clientInfo"] = map[string]string{"name": "fencepost", "version": version.Version}
		copyParams["_meta"] = meta
	}
	m, err := Encode(map[string]any{"jsonrpc": "2.0", "id": c.next.Add(1), "method": method, "params": copyParams})
	if err != nil {
		return nil, err
	}
	var response Message
	if c.stdio != nil {
		response, err = c.stdio.exchange(ctx, m)
	} else {
		response, err = c.http.exchange(ctx, m, c.version)
	}
	if err != nil {
		return nil, err
	}
	result, err := response.Result()
	if err != nil {
		return nil, err
	}
	var envelope struct {
		ResultType string `json:"resultType"`
	}
	if json.Unmarshal(result, &envelope) != nil {
		return nil, errors.New("invalid MCP result")
	}
	if envelope.ResultType == "input_required" {
		return nil, errors.New("server requested client input; scanner advertises no client capabilities")
	}
	if envelope.ResultType != "complete" && (envelope.ResultType != "" || c.version == Latest) {
		return nil, errors.New("unsupported or missing MCP resultType")
	}
	return result, nil
}

func (c *Client) negotiate(ctx context.Context) error {
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	result, err := c.Call(probe, "server/discover", nil)
	cancel()
	if err == nil {
		var info struct {
			Supported    []string                   `json:"supportedVersions"`
			Capabilities map[string]json.RawMessage `json:"capabilities"`
			Instructions string                     `json:"instructions"`
		}
		if json.Unmarshal(result, &info) != nil || !slices.Contains(info.Supported, Latest) {
			return errors.New("server does not support the current modern MCP revision")
		}
		c.capabilities, c.instructions = info.Capabilities, info.Instructions
		return nil
	}
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) && (rpcErr.Code == -32020 || rpcErr.Code == -32021 || rpcErr.Code == -32022) {
		return err
	}
	if c.http != nil {
		var httpErr *HTTPError
		legacyHTTP := errors.As(err, &httpErr) && (httpErr.Status == 400 || httpErr.Status == 404 || httpErr.Status == 405)
		if !errors.As(err, &rpcErr) && !legacyHTTP {
			return err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.version = Previous
	if c.stdio != nil {
		c.stdio.mu.Lock()
		c.stdio.legacy = true
		c.stdio.mu.Unlock()
	}
	result, err = c.Call(ctx, "initialize", map[string]any{"protocolVersion": Previous, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "fencepost", "version": version.Version}})
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	var info struct {
		Version      string                     `json:"protocolVersion"`
		Capabilities map[string]json.RawMessage `json:"capabilities"`
		Instructions string                     `json:"instructions"`
	}
	if json.Unmarshal(result, &info) != nil || info.Version != Previous {
		return errors.New("server negotiated an unsupported MCP revision")
	}
	c.capabilities, c.instructions = info.Capabilities, info.Instructions
	notification, _ := Encode(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if c.stdio != nil {
		return c.stdio.send(notification)
	}
	return c.http.notify(ctx, notification, c.version)
}

func (c *Client) Catalog(ctx context.Context) (Catalog, error) {
	catalog := Catalog{Instructions: c.instructions}
	for _, kind := range []string{"tools", "prompts", "resources"} {
		if _, ok := c.capabilities[kind]; !ok {
			continue
		}
		cursor := ""
		seen := map[string]bool{}
		for page := 0; ; page++ {
			if page == 1000 {
				return Catalog{}, errors.New("MCP pagination exceeds 1000 pages")
			}
			params := map[string]any{}
			if cursor != "" {
				params["cursor"] = cursor
			}
			result, err := c.Call(ctx, kind+"/list", params)
			if err != nil {
				return Catalog{}, fmt.Errorf("%s/list: %w", kind, err)
			}
			var data map[string]json.RawMessage
			if json.Unmarshal(result, &data) != nil {
				return Catalog{}, errors.New("invalid MCP list result")
			}
			var items []json.RawMessage
			if raw := data[kind]; len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
				return Catalog{}, errors.New("invalid MCP list items")
			}
			switch kind {
			case "tools":
				for _, raw := range items {
					var tool Tool
					if json.Unmarshal(raw, &tool) != nil || tool.Text("name") == "" || !json.Valid(tool["inputSchema"]) {
						return Catalog{}, errors.New("invalid MCP tool definition")
					}
					catalog.Tools = append(catalog.Tools, tool)
				}
			case "prompts":
				catalog.Prompts = append(catalog.Prompts, items...)
			case "resources":
				catalog.Resources = append(catalog.Resources, items...)
			}
			cursor = ""
			if next, ok := data["nextCursor"]; ok {
				if json.Unmarshal(next, &cursor) != nil {
					return Catalog{}, errors.New("invalid MCP pagination cursor")
				}
			}
			if cursor == "" {
				break
			}
			if seen[cursor] {
				return Catalog{}, errors.New("repeated MCP pagination cursor")
			}
			seen[cursor] = true
		}
	}
	seenTools := map[string]bool{}
	for _, t := range catalog.Tools {
		name := t.Text("name")
		if seenTools[name] {
			return Catalog{}, errors.New("duplicate tool name on server")
		}
		seenTools[name] = true
	}
	return catalog, nil
}

func (c *Client) Close() error {
	if c.stdio != nil {
		return c.stdio.close()
	}
	return c.http.close(c.version)
}
