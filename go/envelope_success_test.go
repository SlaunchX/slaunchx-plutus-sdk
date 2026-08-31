package plutus

import (
	"errors"
	"net/http"
	"testing"
)

// TestEnvelopeSuccessDecision 覆盖统一响应包络的成功判定算法:
// success 布尔字段是唯一权威, 缺失或非布尔时回退 HTTP 2xx。
// 全部使用本地 fixture, 不依赖向量文件。
func TestEnvelopeSuccessDecision(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		wantSuccess bool
		wantCode    string
		wantMessage string
	}{
		{
			name:        "standard success",
			status:      http.StatusOK,
			body:        `{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"ok":true}}`,
			wantSuccess: true,
			wantCode:    "2000",
			wantMessage: "Success",
		},
		{
			name:        "created success",
			status:      http.StatusCreated,
			body:        `{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2001","message":"Created","data":{"ok":true}}`,
			wantSuccess: true,
			wantCode:    "2001",
			wantMessage: "Created",
		},
		{
			name:        "pending approval is a success",
			status:      http.StatusOK,
			body:        `{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2101","message":"Account pending approval","data":{}}`,
			wantSuccess: true,
			wantCode:    "2101",
			wantMessage: "Account pending approval",
		},
		{
			name:        "business failure on http 200",
			status:      http.StatusOK,
			body:        `{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"4022","message":"Validation Error"}`,
			wantSuccess: false,
			wantCode:    "4022",
			wantMessage: "Validation Error",
		},
		{
			name:        "gateway failure",
			status:      http.StatusUnauthorized,
			body:        `{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"API.SIGNATURE_INVALID","message":"signature is invalid"}`,
			wantSuccess: false,
			wantCode:    "API.SIGNATURE_INVALID",
			wantMessage: "signature is invalid",
		},
		{
			name:        "no success field falls back to http 2xx",
			status:      http.StatusOK,
			body:        `{"data":{}}`,
			wantSuccess: true,
			wantCode:    "",
		},
		{
			name:        "no success field falls back to http 5xx",
			status:      http.StatusInternalServerError,
			body:        `{"message":"boom"}`,
			wantSuccess: false,
			wantCode:    "",
			wantMessage: "boom",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp := ParseAPIResponse(tc.status, http.Header{}, []byte(tc.body))
			if got := resp.IsSuccess(); got != tc.wantSuccess {
				t.Fatalf("IsSuccess() = %v, want %v", got, tc.wantSuccess)
			}
			if resp.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", resp.Code, tc.wantCode)
			}
			if resp.Message != tc.wantMessage {
				t.Errorf("Message = %q, want %q", resp.Message, tc.wantMessage)
			}

			err := resp.AsError()
			if tc.wantSuccess {
				if err != nil {
					t.Fatalf("AsError() = %v, want nil", err)
				}
				return
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("AsError() = %T (%v), want *APIError", err, err)
			}
			if string(apiErr.Code) != tc.wantCode {
				t.Errorf("APIError.Code = %q, want %q", apiErr.Code, tc.wantCode)
			}
			if apiErr.Message != tc.wantMessage {
				t.Errorf("APIError.Message = %q, want %q", apiErr.Message, tc.wantMessage)
			}
			if apiErr.HTTPStatus != tc.status {
				t.Errorf("APIError.HTTPStatus = %d, want %d", apiErr.HTTPStatus, tc.status)
			}
			if apiErr.Response != resp {
				t.Error("APIError.Response must point at the parsed response")
			}
		})
	}
}

// TestEnvelopeFieldsParsed 断言包络的 version / timestamp / success 三个字段被解析出来。
func TestEnvelopeFieldsParsed(t *testing.T) {
	body := `{"version":"2.0.0","timestamp":1755600000123,"success":true,"code":"2000","message":"Success","data":{"ok":true}}`
	resp := ParseAPIResponse(http.StatusOK, http.Header{}, []byte(body))
	if resp.Version != "2.0.0" {
		t.Errorf("Version = %q, want \"2.0.0\"", resp.Version)
	}
	if resp.Timestamp != 1755600000123 {
		t.Errorf("Timestamp = %d, want 1755600000123", resp.Timestamp)
	}
	if resp.SuccessFlag == nil || !*resp.SuccessFlag {
		t.Fatalf("SuccessFlag = %v, want a pointer to true", resp.SuccessFlag)
	}
	var data struct {
		OK bool `json:"ok"`
	}
	if err := resp.DecodeData(&data); err != nil || !data.OK {
		t.Errorf("DecodeData: %v, data = %+v", err, data)
	}
}

// TestSuccessFlagOnlyBooleanIsAuthoritative 断言只有布尔字面量的 success 才被采信。
func TestSuccessFlagOnlyBooleanIsAuthoritative(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{name: "success null, http 200", status: http.StatusOK, body: `{"success":null,"code":"2000"}`, want: true},
		{name: "success null, http 500", status: http.StatusInternalServerError, body: `{"success":null}`, want: false},
		{name: "success as string, http 500", status: http.StatusInternalServerError, body: `{"success":"true"}`, want: false},
		{name: "success as number, http 200", status: http.StatusOK, body: `{"success":1}`, want: true},
		{name: "success as number, http 400", status: http.StatusBadRequest, body: `{"success":1}`, want: false},
		{name: "body is not a json object", status: http.StatusOK, body: `[1,2,3]`, want: true},
		{name: "empty body, http 204", status: http.StatusNoContent, body: ``, want: true},
		{name: "empty body, http 502", status: http.StatusBadGateway, body: ``, want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp := ParseAPIResponse(tc.status, http.Header{}, []byte(tc.body))
			if resp.SuccessFlag != nil {
				t.Fatalf("SuccessFlag = %v, want nil (only a JSON boolean is authoritative)", *resp.SuccessFlag)
			}
			if got := resp.IsSuccess(); got != tc.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNumericCodeIsPreserved 断言数字形式的业务错误码不会被丢弃或置空。
func TestNumericCodeIsPreserved(t *testing.T) {
	for _, code := range []string{"4022", "5001"} {
		body := `{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":` + code + `,"message":"boom"}`
		resp := ParseAPIResponse(http.StatusOK, http.Header{}, []byte(body))
		if resp.Code != code {
			t.Errorf("numeric code %s parsed as %q", code, resp.Code)
		}
		var apiErr *APIError
		if !errors.As(resp.AsError(), &apiErr) {
			t.Fatalf("numeric code %s: AsError did not produce *APIError", code)
		}
		if string(apiErr.Code) != code {
			t.Errorf("APIError.Code = %q, want %q", apiErr.Code, code)
		}
		if !IsCode(resp.AsError(), ErrorCode(code)) {
			t.Errorf("IsCode failed for numeric code %s", code)
		}
	}
}

// TestTypedErrorFromLocalFixture 覆盖 *APIError 的模板匹配与重试建议 (本地 fixture)。
func TestTypedErrorFromLocalFixture(t *testing.T) {
	header := http.Header{}
	header.Set(HeaderRequestID, "req_fixture_0001")
	header.Set(HeaderOperationID, "op_fixture_0001")
	header.Set(HeaderRetryAfter, "3")

	resp := ParseAPIResponse(http.StatusTooManyRequests, header,
		[]byte(`{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"REQUEST.RATE_LIMITED","message":"slow down"}`))
	err := resp.AsError()
	if !errors.Is(err, &APIError{Code: CodeRateLimited}) {
		t.Errorf("errors.Is by code failed: %v", err)
	}
	if !errors.Is(err, &APIError{HTTPStatus: http.StatusTooManyRequests}) {
		t.Errorf("errors.Is by status failed: %v", err)
	}
	if !IsCode(err, CodeRateLimited) {
		t.Errorf("IsCode failed: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatal("errors.As failed")
	}
	if apiErr.RequestID != "req_fixture_0001" || apiErr.OperationID != "op_fixture_0001" {
		t.Errorf("ids = %q / %q", apiErr.RequestID, apiErr.OperationID)
	}
	if apiErr.RetryAfter != "3" || !apiErr.Retryable() {
		t.Errorf("retry = %q / %v", apiErr.RetryAfter, apiErr.Retryable())
	}

	unauthorized := ParseAPIResponse(http.StatusUnauthorized, http.Header{},
		[]byte(`{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"API.SIGNATURE_INVALID","message":"signature is invalid"}`))
	err = unauthorized.AsError()
	if !IsCode(err, CodeSignatureInvalid) {
		t.Errorf("IsCode failed: %v", err)
	}
	if errors.As(err, &apiErr) && apiErr.Retryable() {
		t.Error("API.SIGNATURE_INVALID must not be retryable")
	}
}

// TestIsSuccessCode 断言成功码集合的内容与判定函数。
func TestIsSuccessCode(t *testing.T) {
	for _, code := range []string{"2000", "2001", "2002", "2004", "2006", "2101"} {
		if !IsSuccessCode(code) {
			t.Errorf("IsSuccessCode(%q) = false, want true", code)
		}
	}
	for _, code := range []string{"", "0", "2003", "4022", "5001", "API.SIGNATURE_INVALID"} {
		if IsSuccessCode(code) {
			t.Errorf("IsSuccessCode(%q) = true, want false", code)
		}
	}
	if CodeAccountPendingApproval != "2101" {
		t.Errorf("CodeAccountPendingApproval = %q, want \"2101\"", CodeAccountPendingApproval)
	}
	if len(SuccessCodes) != 6 {
		t.Errorf("SuccessCodes has %d entries, want 6", len(SuccessCodes))
	}
	// 成功码不参与成功判定: code 是成功码但 success 为 false 时仍是失败。
	resp := ParseAPIResponse(http.StatusOK, http.Header{},
		[]byte(`{"version":"2.0.0","timestamp":1755600000123,"success":false,"code":"2000","message":"forced failure"}`))
	if resp.IsSuccess() {
		t.Error("the success boolean must win over a success-family code")
	}
}
