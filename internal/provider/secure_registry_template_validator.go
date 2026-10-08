package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Placeholders and limits mirror the Secure Registry backend validation. Keep in sync.
const (
	maxBlockMessageTemplateLen = 500
	maxNoticeTemplateLen       = 300
)

var (
	blockMessagePlaceholders = []string{"package", "version", "control", "reason", "ecosystem"}
	noticePlaceholders       = []string{"package", "count", "versions", "cooldown_days", "details", "ecosystem"}
	placeholderTokenRe       = regexp.MustCompile(`\{\{([^{}]*)\}\}`)
)

// validateMessageTemplate checks a tenant message template the same way the API does:
// bounded length (characters), a single line of printable text, and only known
// {{placeholders}} with no unterminated or stray braces.
func validateMessageTemplate(tmpl string, maxLen int, allowed []string) error {
	if utf8.RuneCountInString(tmpl) > maxLen {
		return fmt.Errorf("must be at most %d characters", maxLen)
	}
	for _, r := range tmpl {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("must be a single line of printable text")
		}
	}
	tokens := placeholderTokenRe.FindAllStringSubmatch(tmpl, -1)
	if strings.Count(tmpl, "{{") != len(tokens) || strings.Count(tmpl, "}}") != len(tokens) {
		return fmt.Errorf("has an unterminated or malformed {{placeholder}}")
	}
	for _, tok := range tokens {
		name := strings.TrimSpace(tok[1])
		known := false
		for _, a := range allowed {
			if a == name {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("uses unknown placeholder {{%s}}; allowed: %s", name, strings.Join(allowed, ", "))
		}
	}
	return nil
}

type messageTemplateValidator struct {
	maxLen  int
	allowed []string
}

// messageTemplate returns a string validator for a Secure Registry message template.
func messageTemplate(maxLen int, allowed []string) validator.String {
	return messageTemplateValidator{maxLen: maxLen, allowed: allowed}
}

func (v messageTemplateValidator) Description(_ context.Context) string {
	return fmt.Sprintf("at most %d characters, one line of printable text, placeholders limited to: %s", v.maxLen, strings.Join(v.allowed, ", "))
}

func (v messageTemplateValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v messageTemplateValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if err := validateMessageTemplate(req.ConfigValue.ValueString(), v.maxLen, v.allowed); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid message template", fmt.Sprintf("%s %s", req.Path, err))
	}
}
