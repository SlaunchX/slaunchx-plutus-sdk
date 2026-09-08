<?php
declare(strict_types=1);

namespace SlaunchX\Plutus;

/** 协议由接入方明确选择，不根据验签失败自动降级。 */
enum ProtocolProfile: string
{
    /** 原有协议：8 行请求、10 行请求绑定响应，RFC 3986 Query。 */
    case REQUEST_BOUND_V1 = 'request-bound-v1';

    /** product 7a98c040：7 行请求、5 行响应，Java form Query。 */
    case PRODUCT_V1 = 'product-v1';
}
