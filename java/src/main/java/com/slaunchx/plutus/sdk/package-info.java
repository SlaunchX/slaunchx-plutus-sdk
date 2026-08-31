/**
 * SlaunchX Plutus 商户 API SDK,协议标识 {@code SLAUNCHX-PLUTUS-API-V1}。
 *
 * <p>只覆盖传输层:请求签名、请求加密、响应验签、敏感响应解密、Webhook 验签与解密;
 * 不建立业务端点模型,业务字段由调用方自行映射。
 *
 * <p>核心原则是逐字节一致:body 只序列化一次,摘要与发送使用同一个字节数组;
 * query 按 SPEC 4.2 严格规范化,遇到不合规输入在本地拒绝而不是发出必然被拒的请求。
 */
package com.slaunchx.plutus.sdk;
