<?php

/**
 * CRL验证示例脚本
 * 
 * 此脚本演示如何使用CRL验证功能检查证书的撤销状态
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Tourze\TLSCertificate\Crypto\SignatureVerifier;
use Tourze\TLSCertificate\Example\ValidateCRLExample;

// 创建签名验证器
$signatureVerifier = new SignatureVerifier();

// 创建验证示例类
$example = new ValidateCRLExample($signatureVerifier);

// 检查命令行参数
if ($argc < 2) {
    echo "用法: php validate_crl.php <证书文件路径> [--force-update]\n";
    exit(1);
}

$certPath = $argv[1];
$forceUpdate = in_array('--force-update', $argv, true);

// 验证证书
$result = $example->validateFromPEMFile($certPath, $forceUpdate);

// 显示验证结果
echo $example->formatValidationResult($result) . "\n\n";

// 显示CRL统计信息
echo $example->printCRLStats() . "\n"; 