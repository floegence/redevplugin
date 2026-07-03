package capability

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const RiskPlanSchemaVersion = "redevplugin.capability.risk_plan.v1"

var ErrInvalidRiskPlan = errors.New("invalid capability risk plan")

type RiskSeverity string

const (
	RiskSeverityInfo     RiskSeverity = "info"
	RiskSeverityLow      RiskSeverity = "low"
	RiskSeverityMedium   RiskSeverity = "medium"
	RiskSeverityHigh     RiskSeverity = "high"
	RiskSeverityCritical RiskSeverity = "critical"
)

type RiskFlag struct {
	ID                   string       `json:"id"`
	Severity             RiskSeverity `json:"severity"`
	Summary              string       `json:"summary"`
	Description          string       `json:"description,omitempty"`
	RequiresConfirmation bool         `json:"requires_confirmation,omitempty"`
	RequiresAdmin        bool         `json:"requires_admin,omitempty"`
	DataLossRisk         bool         `json:"data_loss_risk,omitempty"`
	Destructive          bool         `json:"destructive,omitempty"`
}

type RiskPlan struct {
	SchemaVersion        string         `json:"schema_version"`
	CapabilityID         string         `json:"capability_id,omitempty"`
	BindingID            string         `json:"binding_id,omitempty"`
	Method               string         `json:"method,omitempty"`
	TargetMethod         string         `json:"target_method,omitempty"`
	Action               string         `json:"action,omitempty"`
	Effect               Effect         `json:"effect,omitempty"`
	ResourceRef          string         `json:"resource_ref,omitempty"`
	ResourceDisplayName  string         `json:"resource_display_name,omitempty"`
	Summary              string         `json:"summary"`
	RiskFlags            []RiskFlag     `json:"risk_flags"`
	RequiresConfirmation bool           `json:"requires_confirmation,omitempty"`
	RequiresAdmin        bool           `json:"requires_admin,omitempty"`
	DataLossRisk         bool           `json:"data_loss_risk,omitempty"`
	Destructive          bool           `json:"destructive,omitempty"`
	DenyReason           string         `json:"deny_reason,omitempty"`
	Details              map[string]any `json:"details,omitempty"`
}

func NewRiskPlan(inv Invocation, summary string) RiskPlan {
	return RiskPlan{
		SchemaVersion: RiskPlanSchemaVersion,
		CapabilityID:  strings.TrimSpace(inv.CapabilityID),
		BindingID:     strings.TrimSpace(inv.BindingID),
		Method:        strings.TrimSpace(inv.Method),
		TargetMethod:  strings.TrimSpace(inv.TargetMethod),
		Effect:        inv.Effect,
		Summary:       strings.TrimSpace(summary),
		RiskFlags:     []RiskFlag{},
	}
}

func NormalizeRiskPlanData(data any) (any, error) {
	switch v := data.(type) {
	case nil:
		return nil, nil
	case RiskPlan:
		return NormalizeRiskPlan(v)
	case *RiskPlan:
		if v == nil {
			return nil, nil
		}
		return NormalizeRiskPlan(*v)
	case map[string]any:
		if _, ok := v["schema_version"]; !ok {
			return data, nil
		}
		if err := rejectUnknownRiskPlanMapKeys(v); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("%w: marshal map: %w", ErrInvalidRiskPlan, err)
		}
		var plan RiskPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			return nil, fmt.Errorf("%w: decode map: %w", ErrInvalidRiskPlan, err)
		}
		return NormalizeRiskPlan(plan)
	default:
		return data, nil
	}
}

func NormalizeRiskPlan(plan RiskPlan) (RiskPlan, error) {
	plan.SchemaVersion = strings.TrimSpace(plan.SchemaVersion)
	if plan.SchemaVersion == "" {
		plan.SchemaVersion = RiskPlanSchemaVersion
	}
	if plan.SchemaVersion != RiskPlanSchemaVersion {
		return RiskPlan{}, fmt.Errorf("%w: unsupported schema_version %q", ErrInvalidRiskPlan, plan.SchemaVersion)
	}

	plan.CapabilityID = strings.TrimSpace(plan.CapabilityID)
	plan.BindingID = strings.TrimSpace(plan.BindingID)
	plan.Method = strings.TrimSpace(plan.Method)
	plan.TargetMethod = strings.TrimSpace(plan.TargetMethod)
	plan.Action = strings.TrimSpace(plan.Action)
	plan.ResourceRef = strings.TrimSpace(plan.ResourceRef)
	plan.ResourceDisplayName = strings.TrimSpace(plan.ResourceDisplayName)
	plan.Summary = strings.TrimSpace(plan.Summary)
	plan.DenyReason = strings.TrimSpace(plan.DenyReason)

	if plan.Summary == "" {
		return RiskPlan{}, fmt.Errorf("%w: summary is required", ErrInvalidRiskPlan)
	}
	if plan.Effect != "" && !validRiskEffect(plan.Effect) {
		return RiskPlan{}, fmt.Errorf("%w: unsupported effect %q", ErrInvalidRiskPlan, plan.Effect)
	}
	if plan.RiskFlags == nil {
		plan.RiskFlags = []RiskFlag{}
	}
	seen := map[string]bool{}
	for i := range plan.RiskFlags {
		normalized, err := normalizeRiskFlag(plan.RiskFlags[i])
		if err != nil {
			return RiskPlan{}, fmt.Errorf("risk_flags[%d]: %w", i, err)
		}
		if seen[normalized.ID] {
			return RiskPlan{}, fmt.Errorf("%w: duplicate risk flag id %q", ErrInvalidRiskPlan, normalized.ID)
		}
		seen[normalized.ID] = true
		plan.RiskFlags[i] = normalized
		if normalized.RequiresConfirmation {
			plan.RequiresConfirmation = true
		}
		if normalized.RequiresAdmin {
			plan.RequiresAdmin = true
			plan.RequiresConfirmation = true
		}
		if normalized.DataLossRisk {
			plan.DataLossRisk = true
		}
		if normalized.Destructive {
			plan.Destructive = true
		}
	}
	return plan, nil
}

func normalizeRiskFlag(flag RiskFlag) (RiskFlag, error) {
	flag.ID = strings.TrimSpace(flag.ID)
	flag.Severity = RiskSeverity(strings.ToLower(strings.TrimSpace(string(flag.Severity))))
	flag.Summary = strings.TrimSpace(flag.Summary)
	flag.Description = strings.TrimSpace(flag.Description)
	if flag.ID == "" {
		return RiskFlag{}, fmt.Errorf("%w: id is required", ErrInvalidRiskPlan)
	}
	if strings.ContainsAny(flag.ID, " \t\r\n") {
		return RiskFlag{}, fmt.Errorf("%w: id must not contain whitespace", ErrInvalidRiskPlan)
	}
	if flag.Summary == "" {
		return RiskFlag{}, fmt.Errorf("%w: summary is required", ErrInvalidRiskPlan)
	}
	if !validRiskSeverity(flag.Severity) {
		return RiskFlag{}, fmt.Errorf("%w: unsupported severity %q", ErrInvalidRiskPlan, flag.Severity)
	}
	if flag.RequiresAdmin {
		flag.RequiresConfirmation = true
	}
	return flag, nil
}

func validRiskSeverity(severity RiskSeverity) bool {
	switch severity {
	case RiskSeverityInfo, RiskSeverityLow, RiskSeverityMedium, RiskSeverityHigh, RiskSeverityCritical:
		return true
	default:
		return false
	}
}

func validRiskEffect(effect Effect) bool {
	switch effect {
	case EffectRead, EffectWrite, EffectExecute, EffectDelete, EffectAdmin:
		return true
	default:
		return false
	}
}

func rejectUnknownRiskPlanMapKeys(plan map[string]any) error {
	for key := range plan {
		if !allowedRiskPlanMapKeys[key] {
			return fmt.Errorf("%w: unknown field %q", ErrInvalidRiskPlan, key)
		}
	}
	rawFlags, ok := plan["risk_flags"]
	if !ok || rawFlags == nil {
		return nil
	}
	flags, ok := rawFlags.([]any)
	if !ok {
		return nil
	}
	for i, rawFlag := range flags {
		flag, ok := rawFlag.(map[string]any)
		if !ok {
			continue
		}
		for key := range flag {
			if !allowedRiskFlagMapKeys[key] {
				return fmt.Errorf("%w: risk_flags[%d] unknown field %q", ErrInvalidRiskPlan, i, key)
			}
		}
	}
	return nil
}

var allowedRiskPlanMapKeys = map[string]bool{
	"schema_version":        true,
	"capability_id":         true,
	"binding_id":            true,
	"method":                true,
	"target_method":         true,
	"action":                true,
	"effect":                true,
	"resource_ref":          true,
	"resource_display_name": true,
	"summary":               true,
	"risk_flags":            true,
	"requires_confirmation": true,
	"requires_admin":        true,
	"data_loss_risk":        true,
	"destructive":           true,
	"deny_reason":           true,
	"details":               true,
}

var allowedRiskFlagMapKeys = map[string]bool{
	"id":                    true,
	"severity":              true,
	"summary":               true,
	"description":           true,
	"requires_confirmation": true,
	"requires_admin":        true,
	"data_loss_risk":        true,
	"destructive":           true,
}
