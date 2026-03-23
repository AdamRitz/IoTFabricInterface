package DataAnalyze

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// RuleDBModel 表示 rule 表中的一条记录
type RuleDBModel struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Expression  string    `json:"expression"`
	RuleJSON    string    `json:"ruleJson"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	TagsJSON    string    `json:"tagsJson"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// SaveRuleToMySQL 保存一条 RuleSet 到 MySQL
func SaveRuleToMySQL(db *sql.DB, rule RuleSet, expression string) error {
	ruleBytes, err := json.Marshal(rule)
	if err != nil {
		return err
	}

	tagsBytes, err := json.Marshal(rule.Tags)
	if err != nil {
		return err
	}

	query := `
INSERT INTO rule (
    id, name, description, expression, rule_json, enabled, priority, tags_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    description = VALUES(description),
    expression = VALUES(expression),
    rule_json = VALUES(rule_json),
    enabled = VALUES(enabled),
    priority = VALUES(priority),
    tags_json = VALUES(tags_json),
    updated_at = VALUES(updated_at);
`

	_, err = db.Exec(
		query,
		rule.ID,
		rule.Name,
		rule.Description,
		expression,
		string(ruleBytes),
		rule.Enabled,
		rule.Priority,
		string(tagsBytes),
		rule.CreatedAt,
		rule.UpdatedAt,
	)
	return err
}

// GetRuleByID 从 MySQL 按 id 读取一条规则
func GetRuleByID(db *sql.DB, id string) (RuleSet, string, error) {
	query := `
SELECT expression, rule_json
FROM rule
WHERE id = ?;
`

	var expression string
	var ruleJSON string

	err := db.QueryRow(query, id).Scan(&expression, &ruleJSON)
	if err != nil {
		return RuleSet{}, "", err
	}

	var rule RuleSet
	if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
		return RuleSet{}, "", err
	}

	return rule, expression, nil
}

// ListRulesFromMySQL 查询全部规则
func ListRulesFromMySQL(db *sql.DB) ([]RuleSet, error) {
	query := `
SELECT rule_json
FROM rule
ORDER BY priority DESC, created_at ASC;
`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []RuleSet
	for rows.Next() {
		var ruleJSON string
		if err := rows.Scan(&ruleJSON); err != nil {
			return nil, err
		}

		var rule RuleSet
		if err := json.Unmarshal([]byte(ruleJSON), &rule); err != nil {
			return nil, fmt.Errorf("unmarshal rule_json failed: %w", err)
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// DeleteRuleByID 按 id 删除规则
func DeleteRuleByID(db *sql.DB, id string) error {
	query := `DELETE FROM rule WHERE id = ?`
	_, err := db.Exec(query, id)
	return err
}

// CreateAndSaveRuleFromExpression 根据表达式创建规则并保存到 MySQL
func CreateAndSaveRuleFromExpression(
	db *sql.DB,
	id string,
	name string,
	description string,
	expr string,
	priority int,
	tags []string,
) (RuleSet, error) {
	rule, err := CreateRuleSetFromExpression(id, name, description, expr, priority, tags)
	if err != nil {
		return RuleSet{}, err
	}

	if err := SaveRuleToMySQL(db, rule, expr); err != nil {
		return RuleSet{}, err
	}

	return rule, nil
}
