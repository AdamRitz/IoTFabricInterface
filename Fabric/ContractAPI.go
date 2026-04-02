package Fabric

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	gwpb "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc/status"
)

var contract *client.Contract

type Rule struct {
	RuleID      string `json:"ruleId"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
	UpdatedTxID string `json:"updatedTxId"`
	UpdatedAt   string `json:"updatedAt"`
}

type DataRecord struct {
	TxID            string                 `json:"txId"`
	DeviceID        string                 `json:"deviceId"`
	Fields          map[string]interface{} `json:"fields"`
	Results         []RuleResult           `json:"results"`
	SubmittedAt     string                 `json:"submittedAt"`
	SubmittedAtUnix int64                  `json:"submittedAtUnix"`
	SubmitterID     string                 `json:"submitterId"`
	SubmitterMSP    string                 `json:"submitterMsp"`
}

type DataPage struct {
	Records             []DataRecord `json:"records"`
	Bookmark            string       `json:"bookmark"`
	FetchedRecordsCount int32        `json:"fetchedRecordsCount"`
}

type SubmitDeviceDataRequest struct {
	DeviceID string                 `json:"deviceId"`
	Fields   map[string]interface{} `json:"fields"`
	Results  []RuleResult           `json:"results"`
}

func InitFabric() {

}
func InitContract(name string, network *client.Network) {
	contract = network.GetContract(name)
}

func dumpGatewayError(err error) {
	st := status.Convert(err)
	for _, d := range st.Details() {
		if ed, ok := d.(*gwpb.ErrorDetail); ok {
			fmt.Printf("endorser address=%s mspId=%s msg=%s\n", ed.GetAddress(), ed.GetMspId(), ed.GetMessage())
		}
	}

	var endorseErr *client.EndorseError
	if errors.As(err, &endorseErr) {
		fmt.Printf("tx=%s endorse failed: %v\n", endorseErr.TransactionID, err)
	}

	var submitErr *client.SubmitError
	if errors.As(err, &submitErr) {
		fmt.Printf("tx=%s submit failed: %v\n", submitErr.TransactionID, err)
	}

	var commitStatusErr *client.CommitStatusError
	if errors.As(err, &commitStatusErr) {
		fmt.Printf("tx=%s commit status failed: %v\n", commitStatusErr.TransactionID, err)
	}

	var commitErr *client.CommitError
	if errors.As(err, &commitErr) {
		fmt.Printf("tx=%s commit failed with code=%d: %v\n", commitErr.TransactionID, int32(commitErr.Code), err)
	}
}

func formatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, "", "  "); err != nil {
		return string(data)
	}
	return prettyJSON.String()
}

func unmarshalJSON[T any](data []byte, out *T) error {
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return nil
}

func ContractUpsertRule(ruleID, expression, description string) error {
	_, err := contract.SubmitTransaction("UpsertRule", ruleID, expression, description)
	if err != nil {
		dumpGatewayError(err)
		return fmt.Errorf("UpsertRule transaction failed: %w", err)
	}
	return nil
}

func ContractGetRule(ruleID string) (*Rule, error) {
	data, err := contract.EvaluateTransaction("GetRule", ruleID)
	if err != nil {
		dumpGatewayError(err)
		return nil, fmt.Errorf("GetRule transaction failed: %w", err)
	}

	var rule Rule
	if err := unmarshalJSON(data, &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

func ContractListAllRules() ([]Rule, error) {
	data, err := contract.EvaluateTransaction("ListAllRules")
	if err != nil {
		dumpGatewayError(err)
		return nil, fmt.Errorf("ListAllRules transaction failed: %w", err)
	}

	var rules []Rule
	if err := unmarshalJSON(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func ContractDeleteRule(ruleID string) error {
	_, err := contract.SubmitTransaction("DeleteRule", ruleID)
	if err != nil {
		dumpGatewayError(err)
		return fmt.Errorf("DeleteRule transaction failed: %w", err)
	}
	return nil
}

func ContractBindRuleToDevice(ruleID, deviceID string) error {
	_, err := contract.SubmitTransaction("BindRuleToDevice", ruleID, deviceID)
	if err != nil {
		dumpGatewayError(err)
		return fmt.Errorf("BindRuleToDevice transaction failed: %w", err)
	}
	return nil
}

func ContractUnbindRuleFromDevice(ruleID, deviceID string) error {
	_, err := contract.SubmitTransaction("UnbindRuleFromDevice", ruleID, deviceID)
	if err != nil {
		dumpGatewayError(err)
		return fmt.Errorf("UnbindRuleFromDevice transaction failed: %w", err)
	}
	return nil
}

func ContractListRulesForDevice(deviceID string) ([]Rule, error) {
	data, err := contract.EvaluateTransaction("ListRulesForDevice", deviceID)
	if err != nil {
		dumpGatewayError(err)
		return nil, fmt.Errorf("ListRulesForDevice transaction failed: %w", err)
	}

	var rules []Rule
	if err := unmarshalJSON(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func ContractSubmitDeviceData(deviceID string, fields map[string]interface{}, results []RuleResult) (*DataRecord, error) {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	if results == nil {
		results = []RuleResult{}
	}

	fieldsJSON, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal fields: %w", err)
	}

	resultsJSON, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results: %w", err)
	}

	data, err := contract.SubmitTransaction("SubmitData", deviceID, string(fieldsJSON), string(resultsJSON))
	if err != nil {
		dumpGatewayError(err)
		return nil, fmt.Errorf("SubmitData transaction failed: %w", err)
	}

	var record DataRecord
	if err := unmarshalJSON(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func ContractGetData(txID string) (*DataRecord, error) {
	data, err := contract.EvaluateTransaction("GetData", txID)
	if err != nil {
		dumpGatewayError(err)
		return nil, fmt.Errorf("GetData transaction failed: %w", err)
	}

	var record DataRecord
	if err := unmarshalJSON(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func ContractQueryDataPageByTime(bookmark string) (*DataPage, error) {
	data, err := contract.EvaluateTransaction("QueryDataPageByTime", bookmark)
	if err != nil {
		dumpGatewayError(err)
		return nil, fmt.Errorf("QueryDataPageByTime transaction failed: %w", err)
	}
	var page DataPage
	err = unmarshalJSON(data, &page)
	if err != nil {
		return nil, err
	}
	return &page, nil
}

func ContractQueryDataPageByDevice(deviceID, bookmark string) (*DataPage, error) {
	data, err := contract.EvaluateTransaction("QueryDataPageByDevice", deviceID, bookmark)
	if err != nil {
		dumpGatewayError(err)
		return nil, fmt.Errorf("QueryDataPageByDevice transaction failed: %w", err)
	}
	var page DataPage
	err = unmarshalJSON(data, &page)
	if err != nil {
		return nil, err
	}
	return &page, nil
}
