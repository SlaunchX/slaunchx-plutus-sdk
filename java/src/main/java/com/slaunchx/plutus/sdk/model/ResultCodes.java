package com.slaunchx.plutus.sdk.model;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 平台统一响应包络中的成功码常量。
 *
 * <p><b>本类仅用于文档与便利判定,不是成功判定依据。</b>成功与否的唯一权威是响应体顶层的
 * {@code success} 布尔字段;该字段缺失或不是布尔类型时,回退到 HTTP 2xx。判定实现见
 * {@link ApiResponse#successful()}。
 *
 * <p>成功码族:{@code 2000} {@code 2001} {@code 2002} {@code 2004} {@code 2006},
 * 以及特殊成功码 {@code 2101} —— 账号待审批,登录成功但不签发 JWT,{@code success} 仍为
 * {@code true}。
 */
public final class ResultCodes {

    /** 通用成功。 */
    public static final String SUCCESS = "2000";
    /** 创建成功。 */
    public static final String CREATED = "2001";
    /** 已接受,异步处理中。 */
    public static final String ACCEPTED = "2002";
    /** 成功,无返回内容。 */
    public static final String NO_CONTENT = "2004";
    /** 部分成功。 */
    public static final String PARTIAL_SUCCESS = "2006";
    /**
     * 账号待审批:登录成功但不签发 JWT。
     *
     * <p>这是<b>成功码</b>,响应的 {@code success} 为 {@code true},调用方须按待审批流程处理,
     * 不可当作错误。
     */
    public static final String ACCOUNT_PENDING_APPROVAL = "2101";

    /**
     * 成功码集合,不可变。
     *
     * <p>仅供文档与便利判定使用,不参与 {@link ApiResponse#successful()} 的判定。
     */
    public static final Set<String> SUCCESS_CODES;

    static {
        Set<String> codes = new LinkedHashSet<>();
        codes.add(SUCCESS);
        codes.add(CREATED);
        codes.add(ACCEPTED);
        codes.add(NO_CONTENT);
        codes.add(PARTIAL_SUCCESS);
        codes.add(ACCOUNT_PENDING_APPROVAL);
        SUCCESS_CODES = Collections.unmodifiableSet(codes);
    }

    private ResultCodes() {
    }

    /**
     * 判断给定码是否属于成功码族。
     *
     * <p>便利方法,<b>不可</b>用来替代 {@link ApiResponse#successful()}:平台可能新增成功码,
     * 权威判定始终是 {@code success} 布尔字段。
     *
     * @param code 响应体的 {@code code} 字符串,允许为 {@code null}
     * @return 属于成功码族返回 {@code true}
     */
    public static boolean isSuccessCode(String code) {
        return code != null && SUCCESS_CODES.contains(code);
    }
}
