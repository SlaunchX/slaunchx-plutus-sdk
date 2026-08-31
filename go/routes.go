package plutus

// 已知加密请求端点表 (SPEC 第 3 节「强制加密请求的端点」)。
//
// 这里的字面量是外部路径, 与 AAD 的 routeTemplate 分量取值一致 (见 SealRequest);
// 六语言 SDK (go/java/php/node/python 及本表) 逐字一致, 变更以 SPEC 第 3 节为准。
//
// 设计取舍: 该表只用于 Client.Prepare 里的可选校验, 默认 (Config.StrictEncryptedRouteValidation
// 为零值 false) 不会阻断请求, 只在 stderr 打印一次警告。理由是平台后续可能新增加密端点而 SDK
// 未及时更新, 若默认严格阻断会导致商户请求被 SDK 卡死; 需要强校验的商户可显式开启严格模式。
var EncryptedRouteTemplates = []string{
	"/card-products/10010105/cards/create",
	"/card-products/10010106/shared/cards/create",
	"/card-products/10010106/prepaid/cards/create",
	"/card-products/10010107/prepaid/cards/create",
	"/card-products/10010107/prepaid/cards/recharge",
	"/card-products/10010107/prepaid/cards/withdraw",
}

// encryptedRouteTemplateSet 是 EncryptedRouteTemplates 的查找表, 供 O(1) 判定。
var encryptedRouteTemplateSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(EncryptedRouteTemplates))
	for _, route := range EncryptedRouteTemplates {
		set[route] = struct{}{}
	}
	return set
}()

// IsKnownEncryptedRoute 判定 path 是否在已知加密端点表 EncryptedRouteTemplates 中。
func IsKnownEncryptedRoute(path string) bool {
	_, ok := encryptedRouteTemplateSet[path]
	return ok
}
