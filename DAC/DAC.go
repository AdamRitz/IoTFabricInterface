package DAC

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"
)

type ValueType string

const (
	TypeUnknown ValueType = ""
	TypeBool    ValueType = "bool"
	TypeNumber  ValueType = "number"
	TypeString  ValueType = "string"
)

type LogicOp string

const (
	LogicAnd LogicOp = "AND"
	LogicOr  LogicOp = "OR"
	LogicNot LogicOp = "NOT"
)

type Operator string

const (
	OpEq         Operator = "EQ"          // ==
	OpNe         Operator = "NE"          // !=
	OpGt         Operator = "GT"          // >
	OpGte        Operator = "GTE"         // >=
	OpLt         Operator = "LT"          // <
	OpLte        Operator = "LTE"         // <=
	OpBetween    Operator = "BETWEEN"     // min <= x <= max
	OpNotBetween Operator = "NOT_BETWEEN" // x < min || x > max
	OpIn         Operator = "IN"          // value in values
	OpNotIn      Operator = "NOT_IN"      // value not in values

	OpExists    Operator = "EXISTS"     // field exists
	OpNotExists Operator = "NOT_EXISTS" // field not exists

	OpChanged   Operator = "CHANGED"   // current != previous
	OpUnchanged Operator = "UNCHANGED" // current == previous

	OpDeltaGt  Operator = "DELTA_GT"  // |curr - prev| > threshold
	OpDeltaGte Operator = "DELTA_GTE" // |curr - prev| >= threshold
	OpDeltaLt  Operator = "DELTA_LT"  // |curr - prev| < threshold
	OpDeltaLte Operator = "DELTA_LTE" // |curr - prev| <= threshold
)

type DataPoint struct {
	Key       string
	Value     any
	Timestamp time.Time
}

// 存放到来的数据 current["temperature"] = 85，上一个用于判断值是否变化
type EvalContext struct {
	Current  map[string]any
	Previous map[string]any
	Now      time.Time
}

// 规则集：主要是存储规则节点的 Root
type RuleSet struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Root        RuleNode  `json:"root"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	Tags        []string  `json:"tags"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// 规则节点：规则节点用于表示规则语法，其中用于表示条件判断的，如 x>3 被称为条件节点，用于表示逻辑的，如 A AND B 被称为逻辑节点。所以通常来说 Condition 字段和 Logic 字段只有一个可以被填充。
type RuleNode struct {
	Logic      LogicOp    `json:"logic"`
	Children   []RuleNode `json:"children,omitempty"`
	Condition  *Condition `json:"condition,omitempty"`
	Label      string     `json:"label,omitempty"`
	StopOnFail bool       `json:"stopOnFail,omitempty"`
}

// 条件判断
// Field：要被判断的变量； Operator 判断语句； Type 条件的类型；
type Condition struct {
	Field    string    `json:"field"`
	Operator Operator  `json:"operator"`
	Type     ValueType `json:"type"`

	// 以下为目标值
	Value any `json:"value,omitempty"`

	// BETWEEN / NOT_BETWEEN 使用
	Min any `json:"min,omitempty"`

	Max any `json:"max,omitempty"`

	// IN / NOT_IN 使用
	Values []any `json:"values,omitempty"`

	// 数值比较的容差，避免浮点误差
	Tolerance float64 `json:"tolerance,omitempty"`
}

type ConditionResult struct {
	Field      string     `json:"field"`
	Operator   Operator   `json:"operator"`
	Passed     bool       `json:"passed"`
	Current    any        `json:"current,omitempty"`
	Previous   any        `json:"previous,omitempty"`
	Expected   any        `json:"expected,omitempty"`
	Message    string     `json:"message,omitempty"`
	Condition  *Condition `json:"condition,omitempty"`
	OccurredAt time.Time  `json:"occurredAt"`
}

type EvaluationResult struct {
	RuleID         string            `json:"ruleId"`
	RuleName       string            `json:"ruleName"`
	Passed         bool              `json:"passed"`
	NodeLogic      LogicOp           `json:"nodeLogic"`
	ConditionTrace []ConditionResult `json:"conditionTrace"`
	Message        string            `json:"message"`
	EvaluatedAt    time.Time         `json:"evaluatedAt"`
}

// EvaluateRuleSet
// 作用：
// 对一条完整规则进行计算，得到该规则是否命中以及每个条件的判断轨迹
// 参数含义：
// rule：待执行的规则集
// current：当前上传的数据集合，键为字段名，值为字段值
// previous：上一份历史数据集合，用于变化量和前后对比判断
// 返回值：
// EvaluationResult：规则的最终判断结果
// error：执行过程中出现的错误
func EvaluateRuleSet(rule RuleSet, current map[string]any, previous map[string]any) (EvaluationResult, error) {
	if !rule.Enabled {
		return EvaluationResult{
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			Passed:      true,
			NodeLogic:   rule.Root.Logic,
			Message:     "rule disabled",
			EvaluatedAt: time.Now(),
		}, nil
	}

	ctx := EvalContext{
		Current:  current,
		Previous: previous,
		Now:      time.Now(),
	}

	passed, trace, err := EvaluateNode(rule.Root, ctx)
	if err != nil {
		return EvaluationResult{}, err
	}

	msg := "rule matched"
	if !passed {
		msg = "rule not matched"
	}

	return EvaluationResult{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		Passed:         passed,
		NodeLogic:      rule.Root.Logic,
		ConditionTrace: trace,
		Message:        msg,
		EvaluatedAt:    ctx.Now,
	}, nil
}

// EvaluateNode
// 作用：
// 递归计算规则树中的一个节点，支持条件节点和逻辑组合节点
// 参数含义：
// node：当前待计算的规则节点
// ctx：本次计算使用的上下文，包括当前数据、历史数据和当前时间
// 返回值：
// bool：当前节点是否成立
// []ConditionResult：当前节点及其子节点的条件判断轨迹
// error：执行过程中出现的错误
func EvaluateNode(node RuleNode, ctx EvalContext) (bool, []ConditionResult, error) {
	// 如果是条件节点，就执行并且返回执行结果
	if node.Condition != nil {
		r, err := EvaluateCondition(*node.Condition, ctx)
		if err != nil {
			return false, nil, err
		}
		return r.Passed, []ConditionResult{r}, nil
	}
	// 如果是逻辑节点，但是逻辑节点没有接子节点就属于违规节点
	if len(node.Children) == 0 {
		return false, nil, errors.New("empty logical node")
	}

	// 递归执行子节点
	switch node.Logic {
	// And 处理逻辑
	case LogicAnd:
		all := true
		var trace []ConditionResult
		for _, child := range node.Children {
			// 此处不是 EvaluateCondition 是因为子节点可能是逻辑节点。
			ok, subTrace, err := EvaluateNode(child, ctx)
			if err != nil {
				return false, trace, err
			}
			trace = append(trace, subTrace...)
			if !ok {
				all = false
				if node.StopOnFail {
					return false, trace, nil
				}
			}
		}
		return all, trace, nil
	// Or 处理逻辑
	case LogicOr:
		anyPassed := false
		var trace []ConditionResult
		for _, child := range node.Children {
			ok, subTrace, err := EvaluateNode(child, ctx)
			if err != nil {
				return false, trace, err
			}
			trace = append(trace, subTrace...)
			if ok {
				anyPassed = true
			}
		}
		return anyPassed, trace, nil
	// Not 处理逻辑
	case LogicNot:
		if len(node.Children) != 1 {
			return false, nil, errors.New("NOT node must have exactly one child")
		}
		ok, trace, err := EvaluateNode(node.Children[0], ctx)
		if err != nil {
			return false, trace, err
		}
		return !ok, trace, nil

	default:
		return false, nil, fmt.Errorf("unsupported logic operator: %s", node.Logic)
	}
}

// EvaluateCondition 作用： 对单个条件进行计算，例如数值比较、区间判断、存在性判断、变化判断等
// 参数含义：
// cond：待执行的单条条件
// ctx：本次计算使用的上下文，包括当前数据、历史数据和当前时间
// 返回值：
// ConditionResult：该条件的判断结果和说明信息
// error：执行过程中出现的错误
func EvaluateCondition(cond Condition, ctx EvalContext) (ConditionResult, error) {
	// 创建结果结构体
	result := ConditionResult{
		Field:      cond.Field,
		Operator:   cond.Operator,
		Condition:  &cond,
		OccurredAt: ctx.Now,
	}
	// 取出数据
	curr, currExists := ctx.Current[cond.Field]
	prev, prevExists := ctx.Previous[cond.Field]

	result.Current = curr
	if prevExists {
		result.Previous = prev
	}

	// 单目运算符，存在或者不存在
	switch cond.Operator {
	case OpExists:
		result.Passed = currExists
		result.Message = buildExistsMessage(cond.Field, currExists, true)
		return result, nil

	case OpNotExists:
		result.Passed = !currExists
		result.Message = buildExistsMessage(cond.Field, currExists, false)
		return result, nil
	}
	// 双目运算符必须在值存在的时候才能比较，所以这里先进行条件判断。
	if !currExists {
		result.Passed = false
		result.Message = fmt.Sprintf("field %q not found in current payload", cond.Field)
		return result, nil
	}

	// 双目运算符
	switch cond.Operator {
	case OpEq, OpNe:
		ok, expected, err := compareEqNe(cond, curr)
		if err != nil {
			return result, err
		}
		result.Expected = expected
		result.Passed = ok
		result.Message = buildBasicMessage(cond.Field, cond.Operator, curr, expected, ok)
		return result, nil

	case OpGt, OpGte, OpLt, OpLte:
		ok, expected, err := compareNumeric(cond, curr)
		if err != nil {
			return result, err
		}
		result.Expected = expected
		result.Passed = ok
		result.Message = buildBasicMessage(cond.Field, cond.Operator, curr, expected, ok)
		return result, nil

	case OpBetween, OpNotBetween:
		ok, expected, err := compareBetween(cond, curr)
		if err != nil {
			return result, err
		}
		result.Expected = expected
		result.Passed = ok
		result.Message = buildBasicMessage(cond.Field, cond.Operator, curr, expected, ok)
		return result, nil

	case OpIn, OpNotIn:
		ok, expected, err := compareIn(cond, curr)
		if err != nil {
			return result, err
		}
		result.Expected = expected
		result.Passed = ok
		result.Message = buildBasicMessage(cond.Field, cond.Operator, curr, expected, ok)
		return result, nil

	case OpChanged, OpUnchanged:
		if !prevExists {
			result.Passed = false
			result.Message = fmt.Sprintf("field %q not found in previous payload", cond.Field)
			return result, nil
		}
		ok, err := compareChanged(cond, curr, prev)
		if err != nil {
			return result, err
		}
		result.Passed = ok
		result.Message = buildChangeMessage(cond.Field, cond.Operator, curr, prev, ok)
		return result, nil

	case OpDeltaGt, OpDeltaGte, OpDeltaLt, OpDeltaLte:
		if !prevExists {
			result.Passed = false
			result.Message = fmt.Sprintf("field %q not found in previous payload", cond.Field)
			return result, nil
		}
		ok, threshold, err := compareDelta(cond, curr, prev)
		if err != nil {
			return result, err
		}
		result.Expected = threshold
		result.Passed = ok
		result.Message = buildDeltaMessage(cond.Field, cond.Operator, curr, prev, threshold, ok)
		return result, nil

	default:
		return result, fmt.Errorf("unsupported operator: %s", cond.Operator)
	}
}

// compareEqNe
// 作用：
// 处理等于和不等于比较，支持布尔、数值、字符串以及默认深度比较
// 参数含义：
// cond：当前条件，内部包含目标类型和比较值
// curr：当前字段值
// 返回值：
// bool：条件是否成立
// any：规范化后的期望值
// error：类型转换或比较过程中出现的错误
func compareEqNe(cond Condition, curr any) (bool, any, error) {
	switch cond.Type {
	case TypeBool:
		cv, err := toBool(curr)
		if err != nil {
			return false, nil, err
		}
		ev, err := toBool(cond.Value)
		if err != nil {
			return false, nil, err
		}
		if cond.Operator == OpEq {
			return cv == ev, ev, nil
		}
		return cv != ev, ev, nil

	case TypeNumber:
		cv, err := toFloat64(curr)
		if err != nil {
			return false, nil, err
		}
		ev, err := toFloat64(cond.Value)
		if err != nil {
			return false, nil, err
		}
		equal := nearlyEqual(cv, ev, cond.Tolerance)
		if cond.Operator == OpEq {
			return equal, ev, nil
		}
		return !equal, ev, nil

	case TypeString:
		cv, err := toString(curr)
		if err != nil {
			return false, nil, err
		}
		ev, err := toString(cond.Value)
		if err != nil {
			return false, nil, err
		}
		if cond.Operator == OpEq {
			return cv == ev, ev, nil
		}
		return cv != ev, ev, nil

	default:
		if cond.Operator == OpEq {
			return reflect.DeepEqual(curr, cond.Value), cond.Value, nil
		}
		return !reflect.DeepEqual(curr, cond.Value), cond.Value, nil
	}
}

// compareNumeric
// 作用：
// 处理数值大小比较，包括大于、大于等于、小于、小于等于
// 参数含义：
// cond：当前条件，内部包含比较运算符和阈值
// curr：当前字段值
// 返回值：
// bool：条件是否成立
// any：比较使用的阈值
// error：数值转换或比较过程中出现的错误
func compareNumeric(cond Condition, curr any) (bool, any, error) {
	cv, err := toFloat64(curr)
	if err != nil {
		return false, nil, err
	}
	ev, err := toFloat64(cond.Value)
	if err != nil {
		return false, nil, err
	}

	switch cond.Operator {
	case OpGt:
		return cv > ev, ev, nil
	case OpGte:
		return cv > ev || nearlyEqual(cv, ev, cond.Tolerance), ev, nil
	case OpLt:
		return cv < ev, ev, nil
	case OpLte:
		return cv < ev || nearlyEqual(cv, ev, cond.Tolerance), ev, nil
	default:
		return false, nil, fmt.Errorf("invalid numeric operator: %s", cond.Operator)
	}
}

// compareBetween
// 作用：
// 处理区间比较，包括处于区间内和不处于区间内
// 参数含义：
// cond：当前条件，内部包含最小值和最大值
// curr：当前字段值
// 返回值：
// bool：条件是否成立
// any：包含 min 和 max 的期望区间
// error：数值转换或区间配置错误时返回错误
func compareBetween(cond Condition, curr any) (bool, any, error) {
	cv, err := toFloat64(curr)
	if err != nil {
		return false, nil, err
	}
	minv, err := toFloat64(cond.Min)
	if err != nil {
		return false, nil, err
	}
	maxv, err := toFloat64(cond.Max)
	if err != nil {
		return false, nil, err
	}
	if minv > maxv {
		return false, nil, fmt.Errorf("min > max for field %q", cond.Field)
	}

	inRange := (cv > minv || nearlyEqual(cv, minv, cond.Tolerance)) &&
		(cv < maxv || nearlyEqual(cv, maxv, cond.Tolerance))

	expected := map[string]float64{
		"min": minv,
		"max": maxv,
	}

	if cond.Operator == OpBetween {
		return inRange, expected, nil
	}
	return !inRange, expected, nil
}

// compareIn
// 作用：
// 处理集合成员判断，包括属于集合和不属于集合
// 参数含义：
// cond：当前条件，内部包含待匹配的候选值集合
// curr：当前字段值
// 返回值：
// bool：条件是否成立
// any：规范化后的候选值集合
// error：类型转换过程中出现的错误
func compareIn(cond Condition, curr any) (bool, any, error) {
	switch cond.Type {
	case TypeBool:
		cv, err := toBool(curr)
		if err != nil {
			return false, nil, err
		}
		found := false
		var normalized []bool
		for _, v := range cond.Values {
			bv, err := toBool(v)
			if err != nil {
				return false, nil, err
			}
			normalized = append(normalized, bv)
			if cv == bv {
				found = true
			}
		}
		if cond.Operator == OpIn {
			return found, normalized, nil
		}
		return !found, normalized, nil

	case TypeNumber:
		cv, err := toFloat64(curr)
		if err != nil {
			return false, nil, err
		}
		found := false
		var normalized []float64
		for _, v := range cond.Values {
			fv, err := toFloat64(v)
			if err != nil {
				return false, nil, err
			}
			normalized = append(normalized, fv)
			if nearlyEqual(cv, fv, cond.Tolerance) {
				found = true
			}
		}
		if cond.Operator == OpIn {
			return found, normalized, nil
		}
		return !found, normalized, nil

	case TypeString:
		cv, err := toString(curr)
		if err != nil {
			return false, nil, err
		}
		found := false
		var normalized []string
		for _, v := range cond.Values {
			sv, err := toString(v)
			if err != nil {
				return false, nil, err
			}
			normalized = append(normalized, sv)
			if cv == sv {
				found = true
			}
		}
		if cond.Operator == OpIn {
			return found, normalized, nil
		}
		return !found, normalized, nil

	default:
		found := false
		for _, v := range cond.Values {
			if reflect.DeepEqual(curr, v) {
				found = true
				break
			}
		}
		if cond.Operator == OpIn {
			return found, cond.Values, nil
		}
		return !found, cond.Values, nil
	}
}

// compareChanged
// 作用：
// 处理当前值和历史值是否发生变化的判断
// 参数含义：
// cond：当前条件，内部包含比较类型和容差
// curr：当前字段值
// prev：历史字段值
// 返回值：
// bool：条件是否成立
// error：类型转换过程中出现的错误
func compareChanged(cond Condition, curr any, prev any) (bool, error) {
	switch cond.Type {
	case TypeBool:
		cv, err := toBool(curr)
		if err != nil {
			return false, err
		}
		pv, err := toBool(prev)
		if err != nil {
			return false, err
		}
		changed := cv != pv
		if cond.Operator == OpChanged {
			return changed, nil
		}
		return !changed, nil

	case TypeNumber:
		cv, err := toFloat64(curr)
		if err != nil {
			return false, err
		}
		pv, err := toFloat64(prev)
		if err != nil {
			return false, err
		}
		changed := !nearlyEqual(cv, pv, cond.Tolerance)
		if cond.Operator == OpChanged {
			return changed, nil
		}
		return !changed, nil

	case TypeString:
		cv, err := toString(curr)
		if err != nil {
			return false, err
		}
		pv, err := toString(prev)
		if err != nil {
			return false, err
		}
		changed := cv != pv
		if cond.Operator == OpChanged {
			return changed, nil
		}
		return !changed, nil

	default:
		changed := !reflect.DeepEqual(curr, prev)
		if cond.Operator == OpChanged {
			return changed, nil
		}
		return !changed, nil
	}
}

// compareDelta
// 作用：
// 处理当前值和历史值之间变化量的比较
// 参数含义：
// cond：当前条件，内部包含变化量比较符和阈值
// curr：当前字段值
// prev：历史字段值
// 返回值：
// bool：条件是否成立
// float64：比较使用的阈值
// error：数值转换或比较过程中出现的错误
func compareDelta(cond Condition, curr any, prev any) (bool, float64, error) {
	cv, err := toFloat64(curr)
	if err != nil {
		return false, 0, err
	}
	pv, err := toFloat64(prev)
	if err != nil {
		return false, 0, err
	}
	threshold, err := toFloat64(cond.Value)
	if err != nil {
		return false, 0, err
	}

	delta := math.Abs(cv - pv)

	switch cond.Operator {
	case OpDeltaGt:
		return delta > threshold, threshold, nil
	case OpDeltaGte:
		return delta > threshold || nearlyEqual(delta, threshold, cond.Tolerance), threshold, nil
	case OpDeltaLt:
		return delta < threshold, threshold, nil
	case OpDeltaLte:
		return delta < threshold || nearlyEqual(delta, threshold, cond.Tolerance), threshold, nil
	default:
		return false, 0, fmt.Errorf("invalid delta operator: %s", cond.Operator)
	}
}

// toBool
// 作用：
// 将任意输入值转换为布尔值
// 参数含义：
// v：待转换的输入值
// 返回值：
// bool：转换后的布尔值
// error：无法转换时返回错误
func toBool(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		s := strings.TrimSpace(strings.ToLower(x))
		switch s {
		case "true", "1", "on", "yes":
			return true, nil
		case "false", "0", "off", "no":
			return false, nil
		default:
			return false, fmt.Errorf("cannot convert string %q to bool", x)
		}
	default:
		return false, fmt.Errorf("cannot convert %T to bool", v)
	}
}

// toFloat64
// 作用：
// 将任意常见数值类型或数字字符串转换为 float64
// 参数含义：
// v：待转换的输入值
// 返回值：
// float64：转换后的浮点数值
// error：无法转换时返回错误
func toFloat64(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case float32:
		return float64(x), nil
	case int:
		return float64(x), nil
	case int8:
		return float64(x), nil
	case int16:
		return float64(x), nil
	case int32:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case uint:
		return float64(x), nil
	case uint8:
		return float64(x), nil
	case uint16:
		return float64(x), nil
	case uint32:
		return float64(x), nil
	case uint64:
		return float64(x), nil
	case string:
		var f float64
		_, err := fmt.Sscanf(strings.TrimSpace(x), "%f", &f)
		if err != nil {
			return 0, fmt.Errorf("cannot convert string %q to float64", x)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

// toString
// 作用：
// 将输入值转换为字符串表示
// 参数含义：
// v：待转换的输入值
// 返回值：
// string：转换后的字符串
// error：当前实现通常不返回错误，保留 error 便于后续扩展
func toString(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case []byte:
		return string(x), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}

// nearlyEqual
// 作用：
// 按给定容差判断两个浮点数是否近似相等
// 参数含义：
// a：第一个浮点数
// b：第二个浮点数
// tolerance：允许的误差范围
// 返回值：
// bool：若两者差值不超过容差则返回 true
func nearlyEqual(a, b, tolerance float64) bool {
	if tolerance <= 0 {
		tolerance = 1e-9
	}
	return math.Abs(a-b) <= tolerance
}

// buildExistsMessage
// 作用：
// 构造字段存在性判断的说明文本
// 参数含义：
// field：字段名
// exists：字段当前是否存在
// shouldExist：规则期望字段是否存在
// 返回值：
// string：人类可读的说明信息
func buildExistsMessage(field string, exists bool, shouldExist bool) string {
	if shouldExist {
		if exists {
			return fmt.Sprintf("field %q exists", field)
		}
		return fmt.Sprintf("field %q does not exist", field)
	}
	if !exists {
		return fmt.Sprintf("field %q does not exist", field)
	}
	return fmt.Sprintf("field %q exists", field)
}

// buildBasicMessage
// 作用：
// 构造普通比较类条件的说明文本
// 参数含义：
// field：字段名
// op：比较运算符
// current：当前字段值
// expected：期望值或阈值
// ok：当前条件是否成立
// 返回值：
// string：人类可读的说明信息
func buildBasicMessage(field string, op Operator, current any, expected any, ok bool) string {
	if ok {
		return fmt.Sprintf("field %q passed: current=%v operator=%s expected=%v", field, current, op, expected)
	}
	return fmt.Sprintf("field %q failed: current=%v operator=%s expected=%v", field, current, op, expected)
}

// buildChangeMessage
// 作用：
// 构造变化判断类条件的说明文本
// 参数含义：
// field：字段名
// op：变化类运算符
// current：当前字段值
// previous：历史字段值
// ok：当前条件是否成立
// 返回值：
// string：人类可读的说明信息
func buildChangeMessage(field string, op Operator, current any, previous any, ok bool) string {
	if ok {
		return fmt.Sprintf("field %q passed: current=%v previous=%v operator=%s", field, current, previous, op)
	}
	return fmt.Sprintf("field %q failed: current=%v previous=%v operator=%s", field, current, previous, op)
}

// buildDeltaMessage
// 作用：
// 构造变化量判断类条件的说明文本
// 参数含义：
// field：字段名
// op：变化量运算符
// current：当前字段值
// previous：历史字段值
// threshold：变化量阈值
// ok：当前条件是否成立
// 返回值：
// string：人类可读的说明信息
func buildDeltaMessage(field string, op Operator, current any, previous any, threshold any, ok bool) string {
	if ok {
		return fmt.Sprintf("field %q passed: current=%v previous=%v operator=%s threshold=%v", field, current, previous, op, threshold)
	}
	return fmt.Sprintf("field %q failed: current=%v previous=%v operator=%s threshold=%v", field, current, previous, op, threshold)
}

// SortRuleSetsByPriorityDesc
// 作用：
// 按优先级从高到低对规则集进行排序
// 参数含义：
// rules：待排序的规则集切片
// 返回值：
// []RuleSet：排序后的新切片，不修改原切片内容
func SortRuleSetsByPriorityDesc(rules []RuleSet) []RuleSet {
	out := make([]RuleSet, len(rules))
	copy(out, rules)

	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Priority > out[i].Priority {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// EvaluateRuleSets
// 作用：
// 依次计算多条规则，并按优先级顺序返回所有结果
// 参数含义：
// rules：待执行的规则集列表
// current：当前上传的数据集合
// previous：上一份历史数据集合
// 返回值：
// []EvaluationResult：所有规则的执行结果
// error：任意一条规则执行失败时返回错误
func EvaluateRuleSets(rules []RuleSet, current map[string]any, previous map[string]any) ([]EvaluationResult, error) {
	sorted := SortRuleSetsByPriorityDesc(rules)
	results := make([]EvaluationResult, 0, len(sorted))

	for _, r := range sorted {
		res, err := EvaluateRuleSet(r, current, previous)
		if err != nil {
			return nil, fmt.Errorf("rule %s evaluate failed: %w", r.Name, err)
		}
		results = append(results, res)
	}

	return results, nil
}

// FilterPassed
// 作用：
// 过滤出执行结果中判断通过的规则
// 参数含义：
// results：全部规则的执行结果
// 返回值：
// []EvaluationResult：仅包含 Passed 为 true 的结果
func FilterPassed(results []EvaluationResult) []EvaluationResult {
	out := make([]EvaluationResult, 0)
	for _, r := range results {
		if r.Passed {
			out = append(out, r)
		}
	}
	return out
}

// FilterFailed
// 作用：
// 过滤出执行结果中判断未通过的规则
// 参数含义：
// results：全部规则的执行结果
// 返回值：
// []EvaluationResult：仅包含 Passed 为 false 的结果
func FilterFailed(results []EvaluationResult) []EvaluationResult {
	out := make([]EvaluationResult, 0)
	for _, r := range results {
		if !r.Passed {
			out = append(out, r)
		}
	}
	return out
}

// BuildSimpleNumberCondition
// 作用：
// 快速构造一个简单的数值比较条件
// 参数含义：
// field：字段名
// op：比较运算符
// value：比较阈值
// 返回值：
// Condition：构造好的数值条件
func BuildSimpleNumberCondition(field string, op Operator, value float64) Condition {
	return Condition{
		Field:     field,
		Operator:  op,
		Type:      TypeNumber,
		Value:     value,
		Tolerance: 1e-9,
	}
}

// BuildSimpleBoolCondition
// 作用：
// 快速构造一个简单的布尔比较条件
// 参数含义：
// field：字段名
// op：比较运算符，通常为 EQ 或 NE
// value：目标布尔值
// 返回值：
// Condition：构造好的布尔条件
func BuildSimpleBoolCondition(field string, op Operator, value bool) Condition {
	return Condition{
		Field:    field,
		Operator: op,
		Type:     TypeBool,
		Value:    value,
	}
}

// BuildBetweenNumberCondition
// 作用：
// 快速构造一个数值区间判断条件
// 参数含义：
// field：字段名
// min：区间最小值
// max：区间最大值
// 返回值：
// Condition：构造好的区间条件
func BuildBetweenNumberCondition(field string, min float64, max float64) Condition {
	return Condition{
		Field:     field,
		Operator:  OpBetween,
		Type:      TypeNumber,
		Min:       min,
		Max:       max,
		Tolerance: 1e-9,
	}
}

// BuildExistsCondition
// 作用：
// 快速构造一个字段存在性判断条件
// 参数含义：
// field：字段名
// 返回值：
// Condition：构造好的存在性条件
func BuildExistsCondition(field string) Condition {
	return Condition{
		Field:    field,
		Operator: OpExists,
	}
}

// BuildChangedNumberCondition
// 作用：
// 快速构造一个数值变化判断条件
// 参数含义：
// field：字段名
// tolerance：判断前后数值是否相同所使用的容差
// 返回值：
// Condition：构造好的变化判断条件
func BuildChangedNumberCondition(field string, tolerance float64) Condition {
	return Condition{
		Field:     field,
		Operator:  OpChanged,
		Type:      TypeNumber,
		Tolerance: tolerance,
	}
}

// BuildDeltaGtCondition
// 作用：
// 快速构造一个变化量大于阈值的条件
// 参数含义：
// field：字段名
// threshold：变化量阈值
// 返回值：
// Condition：构造好的变化量条件
func BuildDeltaGtCondition(field string, threshold float64) Condition {
	return Condition{
		Field:     field,
		Operator:  OpDeltaGt,
		Type:      TypeNumber,
		Value:     threshold,
		Tolerance: 1e-9,
	}
}

// NewConditionNode
// 作用：
// 将一个单独条件包装成规则树中的叶子节点
// 参数含义：
// cond：待包装的条件
// 返回值：
// RuleNode：仅包含条件的规则节点
func NewConditionNode(cond Condition) RuleNode {
	return RuleNode{
		Condition: &cond,
	}
}

// NewAndNode
// 作用：
// 构造一个 AND 逻辑节点，要求所有子节点都成立
// 参数含义：
// children：该逻辑节点下的全部子节点
// 返回值：
// RuleNode：构造好的 AND 节点
func NewAndNode(children ...RuleNode) RuleNode {
	return RuleNode{
		Logic:    LogicAnd,
		Children: children,
	}
}

// NewOrNode
// 作用：
// 构造一个 OR 逻辑节点，只要任一子节点成立即可
// 参数含义：
// children：该逻辑节点下的全部子节点
// 返回值：
// RuleNode：构造好的 OR 节点
func NewOrNode(children ...RuleNode) RuleNode {
	return RuleNode{
		Logic:    LogicOr,
		Children: children,
	}
}

// NewNotNode
// 作用：
// 构造一个 NOT 逻辑节点，对单个子节点结果取反
// 参数含义：
// child：需要取反的子节点
// 返回值：
// RuleNode：构造好的 NOT 节点
func NewNotNode(child RuleNode) RuleNode {
	return RuleNode{
		Logic:    LogicNot,
		Children: []RuleNode{child},
	}
}
