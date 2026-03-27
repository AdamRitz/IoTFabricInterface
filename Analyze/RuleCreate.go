package DataAnalyze

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type tokenType int

const (
	tokenEOF tokenType = iota
	tokenLParen
	tokenRParen
	tokenAnd
	tokenOr
	tokenNot
	tokenIdentifier
	tokenNumber
	tokenString
	tokenBool
	tokenLT
	tokenLTE
	tokenGT
	tokenGTE
	tokenEQ
	tokenNE
)

type token struct {
	typ tokenType
	val string
}

// lexer = tokens + pos 指针
type lexer struct {
	input []rune
	pos   int
}

func newLexer(s string) *lexer {
	return &lexer{
		input: []rune(strings.TrimSpace(s)),
		pos:   0,
	}
}

func (l *lexer) nextToken() (token, error) {
	l.skipSpaces()

	if l.pos >= len(l.input) {
		return token{typ: tokenEOF}, nil
	}

	ch := l.input[l.pos]

	switch ch {
	case '(':
		l.pos++
		return token{typ: tokenLParen, val: "("}, nil
	case ')':
		l.pos++
		return token{typ: tokenRParen, val: ")"}, nil
	case '<':
		l.pos++
		if l.pos < len(l.input) && l.input[l.pos] == '=' {
			l.pos++
			return token{typ: tokenLTE, val: "<="}, nil
		}
		return token{typ: tokenLT, val: "<"}, nil
	case '>':
		l.pos++
		if l.pos < len(l.input) && l.input[l.pos] == '=' {
			l.pos++
			return token{typ: tokenGTE, val: ">="}, nil
		}
		return token{typ: tokenGT, val: ">"}, nil
	case '=':
		l.pos++
		if l.pos < len(l.input) && l.input[l.pos] == '=' {
			l.pos++
			return token{typ: tokenEQ, val: "=="}, nil
		}
		return token{}, fmt.Errorf("unexpected '=' , use '=='")
	case '!':
		l.pos++
		if l.pos < len(l.input) && l.input[l.pos] == '=' {
			l.pos++
			return token{typ: tokenNE, val: "!="}, nil
		}
		return token{}, fmt.Errorf("unexpected '!' , use '!='")
	case '"':
		return l.readString()
	}

	if isIdentifierStart(ch) {
		return l.readIdentifierOrKeyword(), nil
	}

	if unicode.IsDigit(ch) || ch == '-' {
		return l.readNumber()
	}

	return token{}, fmt.Errorf("unexpected character: %q", ch)
}

// 跳过空格，移动指针 pos
func (l *lexer) skipSpaces() {
	for l.pos < len(l.input) && unicode.IsSpace(l.input[l.pos]) {
		l.pos++
	}
}

func (l *lexer) readString() (token, error) {
	l.pos++
	start := l.pos

	for l.pos < len(l.input) && l.input[l.pos] != '"' {
		l.pos++
	}

	if l.pos >= len(l.input) {
		return token{}, fmt.Errorf("unterminated string")
	}

	val := string(l.input[start:l.pos])
	l.pos++
	return token{typ: tokenString, val: val}, nil
}

func (l *lexer) readIdentifierOrKeyword() token {
	start := l.pos
	for l.pos < len(l.input) && isIdentifierPart(l.input[l.pos]) {
		l.pos++
	}

	word := string(l.input[start:l.pos])
	upper := strings.ToUpper(word)

	switch upper {
	case "AND":
		return token{typ: tokenAnd, val: upper}
	case "OR":
		return token{typ: tokenOr, val: upper}
	case "NOT":
		return token{typ: tokenNot, val: upper}
	case "TRUE", "FALSE":
		return token{typ: tokenBool, val: strings.ToLower(word)}
	default:
		return token{typ: tokenIdentifier, val: word}
	}
}

func (l *lexer) readNumber() (token, error) {
	start := l.pos

	if l.input[l.pos] == '-' {
		l.pos++
	}

	dotSeen := false
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if unicode.IsDigit(ch) {
			l.pos++
			continue
		}
		if ch == '.' && !dotSeen {
			dotSeen = true
			l.pos++
			continue
		}
		break
	}

	numStr := string(l.input[start:l.pos])
	if _, err := strconv.ParseFloat(numStr, 64); err != nil {
		return token{}, fmt.Errorf("invalid number: %s", numStr)
	}

	return token{typ: tokenNumber, val: numStr}, nil
}

func isIdentifierStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

func isIdentifierPart(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.'
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) current() token {
	if p.pos >= len(p.tokens) {
		return token{typ: tokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) consume() token {
	tok := p.current()
	p.pos++
	return tok
}

func (p *parser) expect(tt tokenType) (token, error) {
	tok := p.current()
	if tok.typ != tt {
		return token{}, fmt.Errorf("unexpected token %q", tok.val)
	}
	p.pos++
	return tok, nil
}

// orExpr := andExpr { OR andExpr }
func (p *parser) parseOr() (RuleNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return RuleNode{}, err
	}

	children := []RuleNode{left}

	for p.current().typ == tokenOr {
		p.consume()

		right, err := p.parseAnd()
		if err != nil {
			return RuleNode{}, err
		}
		children = append(children, right)
	}

	if len(children) == 1 {
		return left, nil
	}

	return NewOrNode(children...), nil
}

// andExpr := unaryExpr { AND unaryExpr }
func (p *parser) parseAnd() (RuleNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return RuleNode{}, err
	}

	children := []RuleNode{left}

	for p.current().typ == tokenAnd {
		p.consume()

		right, err := p.parseUnary()
		if err != nil {
			return RuleNode{}, err
		}
		children = append(children, right)
	}

	if len(children) == 1 {
		return left, nil
	}

	return NewAndNode(children...), nil
}

// unaryExpr := NOT unaryExpr | primary
func (p *parser) parseUnary() (RuleNode, error) {
	if p.current().typ != tokenNot {
		return p.parsePrimary()
	}

	p.consume()

	node, err := p.parseUnary()
	if err != nil {
		return RuleNode{}, err
	}

	return NewNotNode(node), nil
}

// primary := '(' orExpr ')' | comparison
func (p *parser) parsePrimary() (RuleNode, error) {
	if p.current().typ != tokenLParen {
		return p.parseComparison()
	}

	p.consume()

	node, err := p.parseOr()
	if err != nil {
		return RuleNode{}, err
	}

	if _, err := p.expect(tokenRParen); err != nil {
		return RuleNode{}, fmt.Errorf("missing closing ')'")
	}

	return node, nil
}

// comparison := IDENT OP VALUE
func (p *parser) parseComparison() (RuleNode, error) {
	fieldTok, err := p.expect(tokenIdentifier)
	if err != nil {
		return RuleNode{}, fmt.Errorf("field expected")
	}

	opTok := p.consume()

	var op Operator
	switch opTok.typ {
	case tokenLT:
		op = OpLt
	case tokenLTE:
		op = OpLte
	case tokenGT:
		op = OpGt
	case tokenGTE:
		op = OpGte
	case tokenEQ:
		op = OpEq
	case tokenNE:
		op = OpNe
	default:
		return RuleNode{}, fmt.Errorf("comparison operator expected after field %q", fieldTok.val)
	}

	valTok := p.consume()

	cond := Condition{
		Field:    fieldTok.val,
		Operator: op,
	}

	switch valTok.typ {
	case tokenNumber:
		v, _ := strconv.ParseFloat(valTok.val, 64)
		cond.Type = TypeNumber
		cond.Value = v
		cond.Tolerance = 1e-9
	case tokenString:
		cond.Type = TypeString
		cond.Value = valTok.val
	case tokenBool:
		cond.Type = TypeBool
		cond.Value = strings.EqualFold(valTok.val, "true")
	default:
		return RuleNode{}, fmt.Errorf("value expected after operator for field %q", fieldTok.val)
	}

	return NewConditionNode(cond), nil
}

func tokenizeRuleExpression(expr string) ([]token, error) {
	l := newLexer(expr)
	var tokens []token

	for {
		tok, err := l.nextToken()
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, tok)
		if tok.typ == tokenEOF {
			break
		}
	}

	return tokens, nil
}

// ParseRuleExpression 把字符串表达式解析成规则树，入口函数
// 传入 String 输出 RuleNode 根节点 root
func ParseRuleExpression(expr string) (RuleNode, error) {
	tokens, err := tokenizeRuleExpression(expr)
	if err != nil {
		return RuleNode{}, err
	}

	p := parser{
		tokens: tokens,
		pos:    0,
	}

	root, err := p.parseOr()
	if err != nil {
		return RuleNode{}, err
	}

	if p.current().typ != tokenEOF {
		return RuleNode{}, fmt.Errorf("unexpected trailing token: %q", p.current().val)
	}

	return root, nil
}

// CreateRuleSetFromExpression 根据字符串规则创建 RuleSet，真正入口函数。
func CreateRuleSetFromExpression(id string, name string, description string, expr string, priority int, tags []string) (RuleSet, error) {
	root, err := ParseRuleExpression(expr)
	if err != nil {
		return RuleSet{}, err
	}

	now := time.Now()
	return RuleSet{
		ID:          id,
		Name:        name,
		Description: description,
		Root:        root,
		Enabled:     true,
		Priority:    priority,
		Tags:        tags,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// ToRuleJSON 把规则转成 JSON，方便存数据库
func ToRuleJSON(rule RuleSet) ([]byte, error) {
	return json.Marshal(rule)
}
