package plutus

// 统一响应包络的成功族结果码。
//
// 这些常量只作文档与便利用途, 不参与成功判定: 成功与否以包络的 success 布尔字段为准
// (缺失时回退 HTTP 状态码), 见 APIResponse.IsSuccess。
const (
	// CodeResultSuccess 是通用成功码。
	CodeResultSuccess = "2000"
	// CodeResultCreated 是资源创建成功码。
	CodeResultCreated = "2001"
	// CodeResultAccepted 是请求已受理成功码。
	CodeResultAccepted = "2002"
	// CodeResultNoContent 是无内容成功码。
	CodeResultNoContent = "2004"
	// CodeResultPartialContent 是部分内容成功码。
	CodeResultPartialContent = "2006"
	// CodeAccountPendingApproval 表示账号待审批: 登录成功但不签发 JWT。
	// 这是一个成功码, 包络的 success 仍为 true。
	CodeAccountPendingApproval = "2101"
)

// SuccessCodes 是统一响应包络的成功码集合。
//
// 仅作文档与便利用途, 不是成功判定依据: 成功判定见 APIResponse.IsSuccess。
// "2101" (账号待审批) 也属于成功码。切勿修改本切片的内容。
var SuccessCodes = []string{
	CodeResultSuccess,
	CodeResultCreated,
	CodeResultAccepted,
	CodeResultNoContent,
	CodeResultPartialContent,
	CodeAccountPendingApproval,
}

// IsSuccessCode 判断 code 是否属于 SuccessCodes。
//
// 仅作文档与便利用途: 判定一次调用是否成功必须用 APIResponse.IsSuccess,
// 它以包络的 success 布尔字段为权威。
func IsSuccessCode(code string) bool {
	for _, c := range SuccessCodes {
		if c == code {
			return true
		}
	}
	return false
}
