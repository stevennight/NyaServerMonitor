package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nyaservermonitor/internal/controller/store"
	"nyaservermonitor/internal/shared/model"
)

type alertEngine struct {
	store  *store.Store
	log    *slog.Logger
	box    *secretBox
	client *http.Client
	mu     sync.Mutex
}

func newAlertEngine(st *store.Store, box *secretBox, log *slog.Logger) *alertEngine {
	return &alertEngine{
		store: st,
		box:   box,
		log:   log,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (e *alertEngine) evaluateNode(ctx context.Context, nodeID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	node, err := e.store.GetNode(ctx, nodeID)
	if err != nil {
		return err
	}
	rules, err := e.store.ListAlertRules(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if err := e.evaluateRule(ctx, rule, node, now); err != nil {
			e.log.Warn("evaluate alert rule failed", "rule_id", rule.ID, "node_id", node.ID, "error", err)
		}
	}
	return nil
}

func (e *alertEngine) evaluateAll(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	nodes, err := e.store.ListNodes(ctx)
	if err != nil {
		return err
	}
	rules, err := e.store.ListAlertRules(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, node := range nodes {
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			if err := e.evaluateRule(ctx, rule, node, now); err != nil {
				e.log.Warn("evaluate alert rule failed", "rule_id", rule.ID, "node_id", node.ID, "error", err)
			}
		}
	}
	return nil
}

type alertCondition struct {
	active      bool
	value       float64
	message     string
	fingerprint string
}

func (e *alertEngine) evaluateRule(ctx context.Context, rule model.AlertRule, node model.Node, now time.Time) error {
	state, exists, err := e.store.GetAlertState(ctx, rule.ID, node.ID)
	if err != nil {
		return err
	}
	condition := alertConditionFor(rule, node, state, now)
	if !exists {
		state = model.AlertState{RuleID: rule.ID, NodeID: node.ID, Status: "resolved"}
	}
	previousStatus := state.Status
	previousFirst := state.FirstTriggeredAt
	if rule.Type == model.AlertTLSChanged && condition.active {
		state.Status = "resolved"
		state.Value = condition.value
		state.Message = condition.message
		state.Fingerprint = condition.fingerprint
		state.FirstTriggeredAt = time.Time{}
		state.LastEvaluatedAt = now
		state.LastNotifiedAt = now
		eventID, err := e.addEvent(ctx, rule, node, "firing", condition)
		if err != nil {
			return err
		}
		go e.notifyEvent(context.Background(), eventID, rule, node, "firing", condition)
		return e.store.UpsertAlertState(ctx, state)
	}
	state.Value = condition.value
	state.Message = condition.message
	state.Fingerprint = condition.fingerprint
	state.LastEvaluatedAt = now

	if condition.active {
		if previousStatus != "pending" && previousStatus != "firing" {
			state.FirstTriggeredAt = now
			previousFirst = now
			state.Status = "pending"
		}
		if previousFirst.IsZero() {
			state.FirstTriggeredAt = now
			previousFirst = now
		}
		if state.Status == "pending" && (rule.DurationSeconds == 0 || now.Sub(previousFirst) >= time.Duration(rule.DurationSeconds)*time.Second) {
			state.Status = "firing"
		}
		if state.Status == "firing" {
			shouldNotify := previousStatus != "firing"
			if !shouldNotify && rule.CooldownSeconds > 0 && (state.LastNotifiedAt.IsZero() || now.Sub(state.LastNotifiedAt) >= time.Duration(rule.CooldownSeconds)*time.Second) {
				shouldNotify = true
			}
			if shouldNotify {
				state.LastNotifiedAt = now
				kind := "firing"
				if previousStatus == "firing" {
					kind = "reminder"
				}
				eventID, err := e.addEvent(ctx, rule, node, kind, condition)
				if err != nil {
					return err
				}
				go e.notifyEvent(context.Background(), eventID, rule, node, kind, condition)
			}
		}
	} else {
		if previousStatus == "firing" {
			eventID, err := e.addEvent(ctx, rule, node, "resolved", condition)
			if err != nil {
				return err
			}
			go e.notifyEvent(context.Background(), eventID, rule, node, "resolved", condition)
		}
		state.Status = "resolved"
		state.FirstTriggeredAt = time.Time{}
	}
	return e.store.UpsertAlertState(ctx, state)
}

func alertConditionFor(rule model.AlertRule, node model.Node, previous model.AlertState, now time.Time) alertCondition {
	switch rule.Type {
	case model.AlertNodeOffline:
		return alertCondition{active: node.Status == model.NodeOffline, value: 1, message: "节点超过离线阈值未上报"}
	case model.AlertServiceDown:
		var names []string
		for _, check := range node.Checks {
			if check.Status == "down" {
				names = append(names, check.Name)
			}
		}
		return alertCondition{active: len(names) > 0, value: float64(len(names)), message: "服务检查失败: " + strings.Join(names, ", ")}
	case model.AlertCPUHigh:
		value := node.Metrics.CPUPercent
		return thresholdCondition(value >= rule.Threshold, value, fmt.Sprintf("CPU 使用率 %.1f%%", value))
	case model.AlertMemoryHigh:
		value := percent(node.Metrics.MemoryUsedBytes, node.Metrics.MemoryTotalBytes)
		return thresholdCondition(value >= rule.Threshold, value, fmt.Sprintf("内存使用率 %.1f%%", value))
	case model.AlertDiskHigh:
		value := 0.0
		device := ""
		for _, disk := range node.Metrics.Disks {
			current := percent(disk.UsedBytes, disk.TotalBytes)
			if current > value {
				value = current
				device = disk.Device
				if device == "" {
					device = disk.Mount
				}
			}
		}
		return thresholdCondition(value >= rule.Threshold, value, fmt.Sprintf("磁盘 %s 使用率 %.1f%%", device, value))
	case model.AlertLatencyHigh:
		value := 0.0
		name := ""
		for _, check := range node.Checks {
			if float64(check.LatencyMS) > value {
				value = float64(check.LatencyMS)
				name = check.Name
			}
		}
		return thresholdCondition(value >= rule.Threshold, value, fmt.Sprintf("检查 %s 延迟 %.0f ms", name, value))
	case model.AlertPacketLossHigh:
		value := 0.0
		name := ""
		for _, check := range node.Checks {
			if check.PacketLossPercent > value {
				value = check.PacketLossPercent
				name = check.Name
			}
		}
		return thresholdCondition(value >= rule.Threshold, value, fmt.Sprintf("Ping %s 丢包率 %.1f%%", name, value))
	case model.AlertTLSExpiring:
		value := 0.0
		name := ""
		found := false
		for _, check := range node.Checks {
			if check.Type != "tls" || check.TLSExpiresAtUnix <= 0 {
				continue
			}
			remaining := float64(check.TLSExpiresAtUnix - now.Unix())
			if remaining <= rule.Threshold && (!found || remaining < value) {
				value = remaining
				name = check.Name
				found = true
			}
		}
		return thresholdCondition(found, value, fmt.Sprintf("TLS 证书 %s 将在 %.0f 秒后到期", name, value))
	case model.AlertTLSChanged:
		for _, check := range node.Checks {
			if check.Type == "tls" && check.TLSFingerprint != "" {
				changed := previous.Fingerprint != "" && previous.Fingerprint != check.TLSFingerprint
				return alertCondition{active: changed, value: 1, message: "TLS 证书指纹发生变化", fingerprint: check.TLSFingerprint}
			}
		}
		return alertCondition{fingerprint: previous.Fingerprint}
	case model.AlertTLSInvalid:
		for _, check := range node.Checks {
			if check.Type == "tls" && check.Status != "up" {
				return alertCondition{active: true, value: 1, message: "TLS 证书或握手校验失败", fingerprint: check.TLSFingerprint}
			}
		}
	}
	return alertCondition{}
}

func thresholdCondition(active bool, value float64, message string) alertCondition {
	return alertCondition{active: active, value: value, message: message}
}

func percent(used, total uint64) float64 {
	if total == 0 || used > total {
		return 0
	}
	return float64(used) / float64(total) * 100
}

func (e *alertEngine) addEvent(ctx context.Context, rule model.AlertRule, node model.Node, kind string, condition alertCondition) (int64, error) {
	return e.store.AddAlertEvent(ctx, model.AlertEvent{
		RuleID:    rule.ID,
		RuleName:  rule.Name,
		NodeID:    node.ID,
		NodeName:  node.Name,
		Kind:      kind,
		Value:     condition.value,
		Message:   condition.message,
		CreatedAt: time.Now().UTC(),
	})
}

type notificationChannel struct {
	model.NotificationChannel
	target string
	secret string
}

func (e *alertEngine) notifyEvent(ctx context.Context, eventID int64, rule model.AlertRule, node model.Node, kind string, condition alertCondition) {
	records, err := e.store.ListNotificationChannelRecords(ctx)
	if err != nil {
		e.log.Warn("load notification channels failed", "error", err)
		return
	}
	allowed := make(map[string]struct{}, len(rule.ChannelIDs))
	for _, id := range rule.ChannelIDs {
		allowed[id] = struct{}{}
	}
	channels := make([]notificationChannel, 0, len(records))
	for _, record := range records {
		if !record.Channel.Enabled {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[record.Channel.ID]; !ok {
				continue
			}
		}
		target, targetErr := e.box.open(record.TargetCiphertext)
		secret, secretErr := e.box.open(record.SecretCiphertext)
		if targetErr != nil || (record.SecretCiphertext != "" && secretErr != nil) {
			e.log.Warn("decrypt notification channel failed", "channel_id", record.Channel.ID)
			continue
		}
		channels = append(channels, notificationChannel{NotificationChannel: record.Channel, target: target, secret: secret})
	}
	if len(channels) == 0 {
		return
	}
	payload := map[string]any{
		"event":       kind,
		"rule":        rule.Name,
		"rule_type":   rule.Type,
		"node":        node.Name,
		"node_id":     node.ID,
		"value":       condition.value,
		"message":     condition.message,
		"occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	success := false
	for _, channel := range channels {
		var sendErr error
		switch channel.Type {
		case "webhook":
			sendErr = e.sendWebhook(ctx, channel, payload)
		case "telegram":
			sendErr = e.sendTelegram(ctx, channel, rule, node, kind, condition)
		default:
			sendErr = errors.New("unsupported notification channel")
		}
		if sendErr != nil {
			e.log.Warn("send notification failed", "channel_id", channel.ID, "error", sendErr)
			continue
		}
		success = true
	}
	if success {
		if err := e.store.MarkAlertEventNotified(context.Background(), eventID); err != nil {
			e.log.Warn("mark alert event notified failed", "event_id", eventID, "error", err)
		}
	}
}

func (e *alertEngine) sendWebhook(ctx context.Context, channel notificationChannel, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, channel.target, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if channel.secret != "" {
		digest := hmac.New(sha256.New, []byte(channel.secret))
		_, _ = digest.Write(body)
		request.Header.Set("X-NyaSM-Signature", hex.EncodeToString(digest.Sum(nil)))
	}
	response, err := e.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (e *alertEngine) sendTelegram(ctx context.Context, channel notificationChannel, rule model.AlertRule, node model.Node, kind string, condition alertCondition) error {
	payload, err := json.Marshal(map[string]string{
		"chat_id": channel.target,
		"text":    fmt.Sprintf("NyaServerMonitor %s\n规则：%s\n节点：%s\n%s", kind, rule.Name, node.Name, condition.message),
	})
	if err != nil {
		return err
	}
	endpoint := "https://api.telegram.org/bot" + url.PathEscape(channel.secret) + "/sendMessage"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := e.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("Telegram returned HTTP %d", response.StatusCode)
	}
	return nil
}

func validateNotificationTarget(kind, target, secret string) error {
	if kind == "webhook" {
		parsed, err := url.Parse(strings.TrimSpace(target))
		if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return errors.New("webhook target must be an http or https URL")
		}
		if len(target) > 2048 || len(secret) > 512 {
			return errors.New("webhook target or secret is too long")
		}
		return nil
	}
	if kind == "telegram" {
		if len(target) < 1 || len(target) > 64 || len(secret) < 20 || len(secret) > 256 {
			return errors.New("invalid Telegram chat ID or bot token")
		}
		for _, char := range target {
			if (char < '0' || char > '9') && char != '-' {
				return errors.New("Telegram chat ID must contain only digits and hyphens")
			}
		}
		return nil
	}
	return errors.New("notification type must be webhook or telegram")
}
