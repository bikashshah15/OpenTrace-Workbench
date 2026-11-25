package main

// ECMA-430 message codec for Evidence Specialist B. Independent of Investigator A:
// field names and Format values are parsed case-insensitively; output uses the
// canonical capitalization.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const correlationSubformat = "conversation_opentrace-a"

// contractTokenSubformat marks a major 2 request (I2-REQ-02): a major 2 payload is processed only
// when this token submessage carries "2.0".
const contractTokenSubformat = "contract_opentrace-evidence"

var nlipFormats = map[string]bool{"text": true, "token": true, "structured": true, "binary": true, "location": true, "generic": true}

// Part is a submessage; Message is the top-level NLIP message.
type Part struct {
	Label     *string         `json:"Label,omitempty"`
	Format    string          `json:"Format"`
	Subformat string          `json:"Subformat"`
	Content   json.RawMessage `json:"Content"`
}

type Message struct {
	MessageType *string         `json:"MessageType,omitempty"`
	Format      string          `json:"Format"`
	Subformat   string          `json:"Subformat"`
	Content     json.RawMessage `json:"Content"`
	Submessages []Part          `json:"Submessages,omitempty"`
}

func foldKeys(raw json.RawMessage, where string) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("%s is not a JSON object", where)
	}
	out := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		lk := strings.ToLower(k)
		if _, dup := out[lk]; dup {
			return nil, fmt.Errorf("%s has duplicate field %s", where, k)
		}
		out[lk] = v
	}
	return out, nil
}

func parsePart(raw json.RawMessage, where string) (Part, map[string]json.RawMessage, error) {
	var p Part
	f, err := foldKeys(raw, where)
	if err != nil {
		return p, nil, err
	}
	for _, name := range [][2]string{{"format", "Format"}, {"subformat", "Subformat"}, {"content", "Content"}} {
		if _, ok := f[name[0]]; !ok {
			return p, nil, fmt.Errorf("%s missing required field %s", where, name[1])
		}
	}
	var format, subformat string
	if json.Unmarshal(f["format"], &format) != nil || !nlipFormats[strings.ToLower(format)] {
		return p, nil, fmt.Errorf("%s has an invalid Format", where)
	}
	if json.Unmarshal(f["subformat"], &subformat) != nil {
		return p, nil, fmt.Errorf("%s has an invalid Subformat", where)
	}
	p.Format, p.Subformat, p.Content = strings.ToLower(format), subformat, f["content"]
	if lbl, ok := f["label"]; ok && string(lbl) != "null" {
		var s string
		if json.Unmarshal(lbl, &s) != nil {
			return p, nil, fmt.Errorf("%s has an invalid Label", where)
		}
		p.Label = &s
	}
	return p, f, nil
}

// ParseMessage validates the required NLIP fields; any error maps to HTTP 400.
func ParseMessage(body []byte) (*Message, error) {
	if !json.Valid(body) {
		return nil, errors.New("request body is not JSON")
	}
	top, f, err := parsePart(body, "message")
	if err != nil {
		return nil, err
	}
	m := &Message{Format: top.Format, Subformat: top.Subformat, Content: top.Content}
	if mt, ok := f["messagetype"]; ok && string(mt) != "null" {
		var s string
		if json.Unmarshal(mt, &s) != nil {
			return nil, errors.New("MessageType must be a string")
		}
		if strings.EqualFold(s, "control") {
			s = "control"
		}
		m.MessageType = &s
	}
	if subs, ok := f["submessages"]; ok && string(subs) != "null" {
		var items []json.RawMessage
		if json.Unmarshal(subs, &items) != nil {
			return nil, errors.New("Submessages must be an array")
		}
		for i, item := range items {
			p, _, err := parsePart(item, fmt.Sprintf("submessage[%d]", i))
			if err != nil {
				return nil, err
			}
			m.Submessages = append(m.Submessages, p)
		}
	}
	return m, nil
}

func (m *Message) IsControl() bool { return m.MessageType != nil && *m.MessageType == "control" }

// StructuredPayload returns the first structured/json content (string-encoded JSON is accepted).
func (m *Message) StructuredPayload() (json.RawMessage, bool) {
	parts := append([]Part{{Format: m.Format, Subformat: m.Subformat, Content: m.Content}}, m.Submessages...)
	for _, p := range parts {
		if p.Format == "structured" && strings.EqualFold(p.Subformat, "json") {
			var s string
			if json.Unmarshal(p.Content, &s) == nil && json.Valid([]byte(s)) {
				return json.RawMessage(s), true
			}
			return p.Content, true
		}
	}
	return nil, false
}

// CorrelationTokens returns the token submessages that B must echo unchanged.
func (m *Message) CorrelationTokens() []Part {
	var out []Part
	for _, p := range m.Submessages {
		if p.Format == "token" && p.Subformat == correlationSubformat {
			out = append(out, p)
		}
	}
	return out
}

// ContractToken returns the contract-version token submessage, if present.
func (m *Message) ContractToken() (Part, string, bool) {
	for _, p := range m.Submessages {
		if p.Format == "token" && p.Subformat == contractTokenSubformat {
			var v string
			if json.Unmarshal(p.Content, &v) == nil {
				return p, v, true
			}
			return p, "", true
		}
	}
	return Part{}, "", false
}

func textPart(s string) Part {
	b, _ := json.Marshal(s)
	return Part{Format: "text", Subformat: "english", Content: b}
}

func textMessage(s string) *Message {
	b, _ := json.Marshal(s)
	return &Message{Format: "text", Subformat: "english", Content: b}
}

// replyStructured builds a structured/json reply echoing tokens and adding one English summary.
func replyStructured(payload any, control bool, tokens []Part, summary string) (*Message, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	m := &Message{Format: "structured", Subformat: "json", Content: b}
	if control {
		c := "control"
		m.MessageType = &c
	}
	m.Submessages = append(append([]Part{}, tokens...), textPart(summary))
	return m, nil
}
