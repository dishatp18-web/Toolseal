// Package main implements the native TOOLSEAL MCP security plugin for Maxim AI's
// Bifrost Gateway (github.com/maximhq/bifrost, pinned release transports/v2.5.1,
// core/schemas v1.15.2).
//
// Dynamic shared-object (.so) plugins MUST be compiled on Linux or macOS using the
// exact Go compiler version (go1.27.3) and matching core module version used to
// build the dynamically linked Bifrost gateway binary (`make build DYNAMIC=1`):
//
//	go build -buildmode=plugin -o build/toolseal_plugin.so .
//
// Exported symbols verified against framework/plugins/soloader.go (transports/v2.5.1):
//   - Init(config any) error
//   - GetName() string
//   - Cleanup() error
//   - PreMCPHook(*schemas.BifrostContext, *schemas.BifrostMCPRequest) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error)
//   - PostMCPHook(*schemas.BifrostContext, *schemas.BifrostMCPResponse, *schemas.BifrostError) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error)
//   - MarshalConfigForStorage(map[string]any) (map[string]any, error)
//   - RedactConfig(map[string]any) (map[string]any, error)
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

const (
	// PluginName is the unique system identifier expected by Bifrost's plugin loader.
	PluginName = "toolseal-mcp-security"
	// PluginVersion identifies this native plugin build in TOOLSEAL hook telemetry.
	PluginVersion = "1.0.0"

	defaultTimeoutMs = 3000
	minTimeoutMs     = 500
	maxTimeoutMs     = 15000
	maxSummaryBytes  = 512

	ctxKeyShortCircuited schemas.BifrostContextKey = "toolseal-mcp-short-circuited"
	ctxKeyExecutionID    schemas.BifrostContextKey = "toolseal-mcp-execution-id"
	ctxKeyStartTime      schemas.BifrostContextKey = "toolseal-mcp-start-time"
	ctxKeyResolvedTool   schemas.BifrostContextKey = "toolseal-mcp-resolved-tool"
	ctxKeyClientServer   schemas.BifrostContextKey = "toolseal-mcp-client-server"
)

// PluginConfig defines runtime settings loaded from Bifrost's config.json plugins[].config.
// Secrets are never stored in JSON; SharedSecretEnv names the environment variable holding the HMAC secret.
type PluginConfig struct {
	ToolsealURL     string `json:"toolseal_url"`
	TimeoutMs       int    `json:"timeout_ms"`
	SharedSecretEnv string `json:"shared_secret_env"`
	AgentIDPrefix   string `json:"agent_id_prefix"`
	FailClosed      *bool  `json:"fail_closed,omitempty"`
}

// ToolsealPreRequest is the HMAC-signed PreMCPHook payload sent to TOOLSEAL.
type ToolsealPreRequest struct {
	ToolName      string                 `json:"tool_name"`
	Arguments     map[string]interface{} `json:"arguments"`
	AgentID       string                 `json:"agent_id,omitempty"`
	SessionID     string                 `json:"session_id,omitempty"`
	MCPServer     string                 `json:"mcp_server,omitempty"`
	SourceMode    string                 `json:"source_mode"`
	PluginVersion string                 `json:"plugin_version,omitempty"`
}

// ToolsealPreResponse mirrors TOOLSEAL's PreMCPHook inspection decision.
type ToolsealPreResponse struct {
	Allow             bool   `json:"allow"`
	ShortCircuit      bool   `json:"short_circuit"`
	Decision          string `json:"decision"`
	RiskScore         int    `json:"risk_score"`
	Reason            string `json:"reason"`
	ExecutionID       string `json:"execution_id"`
	ExecutionUID      string `json:"execution_uid,omitempty"`
	IncidentID        string `json:"incident_id,omitempty"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
	SourceMode        string `json:"source_mode"`
}

// ToolsealPostRequest is the HMAC-signed PostMCPHook outcome payload sent to TOOLSEAL.
type ToolsealPostRequest struct {
	ExecutionID   string `json:"execution_id,omitempty"`
	ToolName      string `json:"tool_name"`
	DurationMs    int64  `json:"duration_ms"`
	Success       bool   `json:"success"`
	ErrorMessage  string `json:"error_message,omitempty"`
	ResultSummary string `json:"result_summary,omitempty"`
	SourceMode    string `json:"source_mode"`
	PluginVersion string `json:"plugin_version,omitempty"`
}

type runtimeState struct {
	mu              sync.RWMutex
	toolsealBaseURL string
	sharedSecretEnv string
	agentIDPrefix   string
	timeout         time.Duration
	failClosed      bool
	httpClient      *http.Client
}

var state = newDefaultState()

func newDefaultState() *runtimeState {
	timeout := time.Duration(defaultTimeoutMs) * time.Millisecond
	return &runtimeState{
		toolsealBaseURL: strings.TrimRight(getEnv("TOOLSEAL_URL", "http://127.0.0.1:3000"), "/"),
		sharedSecretEnv: "BIFROST_SHARED_SECRET",
		agentIDPrefix:   "bifrost",
		timeout:         timeout,
		failClosed:      true,
		httpClient:      &http.Client{Timeout: timeout},
	}
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// Init initializes the native TOOLSEAL MCP security plugin with configuration passed by Bifrost's loader.
func Init(config any) error {
	next := newDefaultState()

	if config != nil {
		rawBytes, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("toolseal plugin config marshal error: %w", err)
		}
		var parsed PluginConfig
		if err := json.Unmarshal(rawBytes, &parsed); err != nil {
			return fmt.Errorf("toolseal plugin config parse error: %w", err)
		}

		if url := strings.TrimSpace(parsed.ToolsealURL); url != "" {
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				return errors.New("toolseal_url must use http:// or https:// scheme")
			}
			next.toolsealBaseURL = strings.TrimRight(url, "/")
		}

		if parsed.TimeoutMs > 0 {
			ms := parsed.TimeoutMs
			if ms < minTimeoutMs {
				ms = minTimeoutMs
			} else if ms > maxTimeoutMs {
				ms = maxTimeoutMs
			}
			next.timeout = time.Duration(ms) * time.Millisecond
			next.httpClient = &http.Client{Timeout: next.timeout}
		}

		if envName := strings.TrimSpace(parsed.SharedSecretEnv); envName != "" {
			next.sharedSecretEnv = envName
		}

		if prefix := strings.TrimSpace(parsed.AgentIDPrefix); prefix != "" {
			next.agentIDPrefix = prefix
		}

		if parsed.FailClosed != nil {
			next.failClosed = *parsed.FailClosed
		}
	}

	state.mu.Lock()
	if state.httpClient != nil {
		state.httpClient.CloseIdleConnections()
	}
	state.toolsealBaseURL = next.toolsealBaseURL
	state.sharedSecretEnv = next.sharedSecretEnv
	state.agentIDPrefix = next.agentIDPrefix
	state.timeout = next.timeout
	state.failClosed = next.failClosed
	state.httpClient = next.httpClient
	state.mu.Unlock()

	return nil
}

// GetName returns the plugin's canonical Bifrost system identifier (required by BasePlugin).
func GetName() string {
	return PluginName
}

// Cleanup releases idle HTTP connections on Bifrost gateway shutdown (required by BasePlugin).
func Cleanup() error {
	state.mu.RLock()
	client := state.httpClient
	state.mu.RUnlock()
	if client != nil {
		client.CloseIdleConnections()
	}
	return nil
}

// MarshalConfigForStorage ensures literal secrets are never persisted if passed into plugin config.
func MarshalConfigForStorage(cfg map[string]any) (map[string]any, error) {
	if cfg == nil {
		return nil, nil
	}
	cloned := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if strings.Contains(strings.ToLower(k), "secret") && !strings.EqualFold(k, "shared_secret_env") {
			continue
		}
		cloned[k] = v
	}
	return cloned, nil
}

// RedactConfig returns a safe API view of plugin config with any secret fields masked.
func RedactConfig(cfg map[string]any) (map[string]any, error) {
	if cfg == nil {
		return map[string]any{}, nil
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if strings.Contains(strings.ToLower(k), "secret") && !strings.EqualFold(k, "shared_secret_env") {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out, nil
}

func currentRuntimeSnapshot() (baseURL, secretEnv, agentPrefix string, timeout time.Duration, failClosed bool, client *http.Client) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.toolsealBaseURL, state.sharedSecretEnv, state.agentIDPrefix, state.timeout, state.failClosed, state.httpClient
}

func signWebhookRequest(req *http.Request, body []byte, secretEnv string) error {
	secret := strings.TrimSpace(os.Getenv(secretEnv))
	if secret == "" {
		return fmt.Errorf("%s environment variable is required to sign TOOLSEAL webhook requests", secretEnv)
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	timestamp := strconvFormatInt(time.Now().Unix())

	canonical := timestamp + "." + nonce + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-Bifrost-Timestamp", timestamp)
	req.Header.Set("X-Bifrost-Nonce", nonce)
	req.Header.Set("X-Bifrost-Signature", signature)
	return nil
}

func strconvFormatInt(v int64) string {
	return fmt.Sprintf("%d", v)
}

func normalizeToolName(rawName, clientName string) string {
	name := strings.TrimSpace(rawName)
	client := strings.TrimSpace(clientName)
	if name == "" {
		return ""
	}
	if client != "" && strings.HasPrefix(name, client+"-") {
		return strings.TrimPrefix(name, client+"-")
	}
	return name
}

func extractArgumentsMap(rawArgs any) map[string]interface{} {
	if rawArgs == nil {
		return map[string]interface{}{}
	}

	switch typed := rawArgs.(type) {
	case map[string]interface{}:
		return typed
	case *string:
		if typed == nil || strings.TrimSpace(*typed) == "" {
			return map[string]interface{}{}
		}
		var out map[string]interface{}
		if err := json.Unmarshal([]byte(*typed), &out); err == nil && out != nil {
			return out
		}
		return map[string]interface{}{"raw_arguments": *typed}
	case string:
		if strings.TrimSpace(typed) == "" {
			return map[string]interface{}{}
		}
		var out map[string]interface{}
		if err := json.Unmarshal([]byte(typed), &out); err == nil && out != nil {
			return out
		}
		return map[string]interface{}{"raw_arguments": typed}
	case json.RawMessage:
		var out map[string]interface{}
		if err := json.Unmarshal(typed, &out); err == nil && out != nil {
			return out
		}
	default:
		if data, err := json.Marshal(typed); err == nil {
			var out map[string]interface{}
			if err := json.Unmarshal(data, &out); err == nil && out != nil {
				return out
			}
		}
	}
	return map[string]interface{}{}
}

func buildShortCircuit(statusCode int, code string, message string) *schemas.MCPPluginShortCircuit {
	errType := code
	errCode := code
	allowFallbacks := false
	return &schemas.MCPPluginShortCircuit{
		Error: &schemas.BifrostError{
			IsBifrostError: false,
			StatusCode:     &statusCode,
			AllowFallbacks: &allowFallbacks,
			Error: &schemas.ErrorField{
				Type:    &errType,
				Code:    &errCode,
				Message: message,
			},
		},
	}
}

// PreMCPHook intercepts every Bifrost MCP operation prior to upstream tool invocation.
// Matches schemas.MCPPlugin and framework/plugins/soloader.go exact dynamic symbol signature.
func PreMCPHook(ctx *schemas.BifrostContext, req *schemas.BifrostMCPRequest) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error) {
	if req == nil || !req.RequestType.IsExecuteTool() {
		return req, nil, nil
	}

	// Prevent recursive re-entry on already-short-circuited requests
	if ctx != nil {
		if flagged, ok := ctx.Value(ctxKeyShortCircuited).(bool); ok && flagged {
			return req, nil, nil
		}
	}

	toolName := normalizeToolName(req.GetToolName(), req.ClientName)
	if toolName == "" {
		if ctx != nil {
			ctx.SetValue(ctxKeyShortCircuited, true)
		}
		return req, buildShortCircuit(400, "toolseal_invalid_request", "TOOLSEAL rejected MCP call with empty tool name"), nil
	}

	argsMap := extractArgumentsMap(req.GetToolArguments())

	var sessionID string
	var agentID string
	_, _, prefix, _, failClosed, _ := currentRuntimeSnapshot()
	agentID = prefix + ":" + nonEmpty(req.ClientName, "mcp-gateway")

	if ctx != nil {
		if sid, ok := ctx.Value(schemas.BifrostContextKeyMCPSessionID).(string); ok && sid != "" {
			sessionID = sid
		} else if rid, ok := ctx.Value(schemas.BifrostContextKeyRequestID).(string); ok && rid != "" {
			sessionID = rid
		}
		if uid, ok := ctx.Value(schemas.BifrostContextKeyUserID).(string); ok && uid != "" {
			agentID = agentID + ":" + uid
		}
	}

	var parentCtx context.Context = context.Background()
	if ctx != nil {
		parentCtx = ctx
	}

	decision, err := EvaluatePreMCPWithContext(parentCtx, toolName, argsMap, req.ClientName, agentID, sessionID)
	if err != nil {
		if ctx != nil {
			ctx.Log(schemas.LogLevelError, fmt.Sprintf("[TOOLSEAL] PreMCPHook error for tool=%s: %v", toolName, err))
		}
		if failClosed || (decision != nil && decision.ShortCircuit) {
			if ctx != nil {
				ctx.SetValue(ctxKeyShortCircuited, true)
			}
			if decision != nil && decision.ShortCircuit {
				code := "toolseal_security_blocked"
				if decision.Decision == "REVIEW" {
					code = "toolseal_approval_required"
				}
				return req, buildShortCircuit(http.StatusForbidden, code, err.Error()), nil
			}
			return req, buildShortCircuit(http.StatusServiceUnavailable, "toolseal_fail_closed", err.Error()), nil
		}
		return req, nil, nil
	}

	if decision == nil || !decision.Allow || decision.ShortCircuit {
		if ctx != nil {
			ctx.SetValue(ctxKeyShortCircuited, true)
		}
		reason := "TOOLSEAL denied tool execution"
		code := "toolseal_security_blocked"
		if decision != nil {
			if decision.Decision == "REVIEW" {
				code = "toolseal_approval_required"
			}
			if decision.Reason != "" {
				reason = fmt.Sprintf("TOOLSEAL %s (risk %d/100): %s", decision.Decision, decision.RiskScore, decision.Reason)
			}
		}
		return req, buildShortCircuit(http.StatusForbidden, code, reason), nil
	}

	if ctx != nil {
		ctx.SetValue(ctxKeyExecutionID, decision.ExecutionID)
		ctx.SetValue(ctxKeyStartTime, time.Now())
		ctx.SetValue(ctxKeyResolvedTool, toolName)
		ctx.SetValue(ctxKeyClientServer, req.ClientName)
		ctx.Log(schemas.LogLevelInfo, fmt.Sprintf("[TOOLSEAL] PreMCPHook ALLOW tool=%s server=%s risk=%d exec=%s", toolName, req.ClientName, decision.RiskScore, decision.ExecutionUID))
	}

	return req, nil, nil
}

// PostMCPHook reports completed MCP tool execution telemetry to TOOLSEAL without altering or concealing tool responses or errors.
// Matches schemas.MCPPlugin and framework/plugins/soloader.go exact dynamic symbol signature.
func PostMCPHook(ctx *schemas.BifrostContext, resp *schemas.BifrostMCPResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error) {
	// Skip calls already short-circuited by PreMCPHook (Bifrost's pipeline runs PostHooks after short-circuits)
	if ctx != nil {
		if flagged, ok := ctx.Value(ctxKeyShortCircuited).(bool); ok && flagged {
			return resp, bifrostErr, nil
		}
	}

	mcpReqType := schemas.MCPRequestType("")
	clientName := ""
	rawToolName := ""
	var durationMs int64

	if resp != nil {
		mcpReqType = resp.ExtraFields.MCPRequestType
		clientName = resp.ExtraFields.ClientName
		rawToolName = resp.ExtraFields.ToolName
		durationMs = resp.ExtraFields.Latency
	} else if bifrostErr != nil {
		mcpReqType = bifrostErr.ExtraFields.MCPRequestType
		clientName = bifrostErr.ExtraFields.MCPClientName
		rawToolName = bifrostErr.ExtraFields.MCPToolName
	}

	if !mcpReqType.IsExecuteTool() {
		return resp, bifrostErr, nil
	}

	var executionID string
	if ctx != nil {
		if eid, ok := ctx.Value(ctxKeyExecutionID).(string); ok {
			executionID = eid
		}
		if rawToolName == "" {
			if tn, ok := ctx.Value(ctxKeyResolvedTool).(string); ok {
				rawToolName = tn
			}
		}
		if clientName == "" {
			if cn, ok := ctx.Value(ctxKeyClientServer).(string); ok {
				clientName = cn
			}
		}
		if durationMs <= 0 {
			if started, ok := ctx.Value(ctxKeyStartTime).(time.Time); ok && !started.IsZero() {
				durationMs = time.Since(started).Milliseconds()
			}
		}
	}

	toolName := normalizeToolName(rawToolName, clientName)
	if toolName == "" {
		return resp, bifrostErr, nil
	}

	success := bifrostErr == nil
	var errMsg string
	if bifrostErr != nil && bifrostErr.Error != nil {
		errMsg = bifrostErr.Error.Message
	}

	resultSummary := summarizeResponse(resp, &success, &errMsg)

	var parentCtx context.Context = context.Background()
	if ctx != nil {
		parentCtx = ctx
	}

	if err := ReportPostMCPWithContext(parentCtx, executionID, toolName, durationMs, success, errMsg, resultSummary); err != nil && ctx != nil {
		ctx.Log(schemas.LogLevelWarn, fmt.Sprintf("[TOOLSEAL] PostMCPHook telemetry delivery failed for tool=%s: %v", toolName, err))
	}

	// Never overwrite or suppress the original MCP response or tool error
	return resp, bifrostErr, nil
}

func summarizeResponse(resp *schemas.BifrostMCPResponse, success *bool, errMsg *string) string {
	if resp == nil || resp.ChatMessage == nil {
		return ""
	}
	if resp.ChatMessage.ChatToolMessage != nil && resp.ChatMessage.ChatToolMessage.IsError != nil && *resp.ChatMessage.ChatToolMessage.IsError {
		*success = false
		if *errMsg == "" && resp.ChatMessage.Content != nil && resp.ChatMessage.Content.ContentStr != nil {
			*errMsg = truncateString(*resp.ChatMessage.Content.ContentStr, maxSummaryBytes)
		}
	}
	if resp.ChatMessage.Content != nil && resp.ChatMessage.Content.ContentStr != nil {
		return truncateString(*resp.ChatMessage.Content.ContentStr, maxSummaryBytes)
	}
	return ""
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

// EvaluatePreMCP forwards an intercepted MCP tool call to TOOLSEAL's authenticated PreMCPHook endpoint.
func EvaluatePreMCP(toolName string, args map[string]interface{}, mcpServer string, sessionID string) (*ToolsealPreResponse, error) {
	return EvaluatePreMCPWithContext(context.Background(), toolName, args, mcpServer, "", sessionID)
}

// EvaluatePreMCPWithContext forwards an MCP tool execution call with a bounded context timeout and fail-closed handling.
func EvaluatePreMCPWithContext(ctx context.Context, toolName string, args map[string]interface{}, mcpServer, agentID, sessionID string) (*ToolsealPreResponse, error) {
	baseURL, secretEnv, prefix, timeout, _, client := currentRuntimeSnapshot()
	if agentID == "" {
		agentID = prefix + ":" + nonEmpty(mcpServer, "mcp-gateway")
	}
	if args == nil {
		args = map[string]interface{}{}
	}

	payload := ToolsealPreRequest{
		ToolName:      toolName,
		Arguments:     args,
		AgentID:       agentID,
		MCPServer:     mcpServer,
		SessionID:     sessionID,
		SourceMode:    "live",
		PluginVersion: PluginVersion,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/api/bifrost/pre-mcp-hook", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := signWebhookRequest(req, body, secretEnv); err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("toolseal PreMCPHook unreachable (fail-closed): %w", err)
	}
	defer res.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("toolseal PreMCPHook response read failed (fail-closed): %w", err)
	}

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusServiceUnavailable || res.StatusCode >= 500 {
		return nil, fmt.Errorf("toolseal PreMCPHook rejected or unavailable (HTTP %d, fail-closed)", res.StatusCode)
	}

	var decision ToolsealPreResponse
	if err := json.Unmarshal(respBytes, &decision); err != nil {
		return nil, fmt.Errorf("toolseal PreMCPHook invalid response JSON (fail-closed): %w", err)
	}

	if decision.ShortCircuit || !decision.Allow {
		return &decision, fmt.Errorf("TOOLSEAL %s (risk %d/100): %s", decision.Decision, decision.RiskScore, decision.Reason)
	}

	return &decision, nil
}

// ReportPostMCP forwards MCP tool execution outcomes to TOOLSEAL's authenticated PostMCPHook endpoint.
func ReportPostMCP(executionID, toolName string, durationMs int64, success bool, errMsg string) error {
	return ReportPostMCPWithContext(context.Background(), executionID, toolName, durationMs, success, errMsg, "")
}

// ReportPostMCPWithContext forwards MCP tool execution outcomes with bounded timeout and HMAC signing.
func ReportPostMCPWithContext(ctx context.Context, executionID, toolName string, durationMs int64, success bool, errMsg, resultSummary string) error {
	baseURL, secretEnv, _, timeout, _, client := currentRuntimeSnapshot()

	payload := ToolsealPostRequest{
		ExecutionID:   executionID,
		ToolName:      toolName,
		DurationMs:    durationMs,
		Success:       success,
		ErrorMessage:  errMsg,
		ResultSummary: resultSummary,
		SourceMode:    "live",
		PluginVersion: PluginVersion,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, baseURL+"/api/bifrost/post-mcp-hook", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := signWebhookRequest(req, body, secretEnv); err != nil {
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return fmt.Errorf("toolseal PostMCPHook rejected request (HTTP %d)", res.StatusCode)
	}
	return nil
}
