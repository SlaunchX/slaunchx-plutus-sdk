<?php
declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';

use SlaunchX\Plutus\Exception\ApiException;
use SlaunchX\Plutus\PlutusClient;
use SlaunchX\Plutus\PlutusConfig;
use SlaunchX\Plutus\ProtocolProfile;

// Set SLAUNCHX_BASE_URL, SLAUNCHX_API_KEY, MERCHANT_AUTH_PRIVATE_PEM_FILE,
// PLATFORM_AUTH_PUBLIC_PEM_FILE. Use --check to validate without calling the API.
$required = static function (string $name): string {
    $value = getenv($name);
    if ($value === false || trim($value) === '') {
        throw new RuntimeException('Missing configuration: ' . $name);
    }
    return $value;
};
$pem = static function (string $name) use ($required): string {
    $path = $required($name);
    if (!is_file($path) || !is_readable($path)) {
        throw new RuntimeException('Cannot read key file configured by: ' . $name);
    }
    $contents = file_get_contents($path);
    if ($contents === false || $contents === '') {
        throw new RuntimeException('Empty key file configured by: ' . $name);
    }
    return $contents;
};

try {
    $config = new PlutusConfig(
        baseUrl: $required('SLAUNCHX_BASE_URL'),
        apiKey: $required('SLAUNCHX_API_KEY'),
        merchantAuthPrivateKeyPem: $pem('MERCHANT_AUTH_PRIVATE_PEM_FILE'),
        platformAuthPublicKeyPem: $pem('PLATFORM_AUTH_PUBLIC_PEM_FILE'),
        protocolProfile: ProtocolProfile::PRODUCT_V1,
    );
    $config->merchantAuthPrivateKey();
    $config->platformAuthPublicKey();
    if (($argv[1] ?? '') === '--check') {
        echo "Configuration valid, protocol=product-v1; no API request sent.\n";
        exit(0);
    }
    $client = new PlutusClient($config);
    foreach ([
        ['GET', '/card-products/cards/page', ['query' => ['page' => 0, 'size' => 10]]],
        ['POST', '/card-products/groups/list', ['json' => ['isActive' => true]]],
    ] as [$method, $path, $options]) {
        $response = $client->request($method, $path, $options);
        $ok = $response->statusCode >= 200 && $response->statusCode < 300
            && $response->signatureVerified && $response->successFlag() === true;
        echo json_encode(['method' => $method, 'path' => $path, 'httpStatus' => $response->statusCode,
            'signatureVerified' => $response->signatureVerified, 'success' => $ok,
            'requestId' => $response->requestId()], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), PHP_EOL;
        if (!$ok) exit(1);
    }
} catch (ApiException $error) {
    fwrite(STDERR, json_encode(['httpStatus' => $error->statusCode(), 'code' => $error->rawErrorCode(),
        'requestId' => $error->requestId()], JSON_THROW_ON_ERROR) . PHP_EOL);
    exit(1);
} catch (Throwable $error) {
    // Only our own configuration errors are printed verbatim; SDK failures may carry response details.
    fwrite(STDERR, ($error::class === RuntimeException::class ? $error->getMessage() : $error::class) . PHP_EOL);
    exit(2);
}
