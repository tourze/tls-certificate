<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Revocation\OCSP;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Crypto\SignatureVerifier;
use Tourze\TLSCertificate\Exception\OCSPException;
use Tourze\TLSCertificate\Revocation\OCSP\OCSPRequest;
use Tourze\TLSCertificate\Revocation\OCSP\OCSPResponse;

/**
 * OCSPResponse测试类
 */
class OCSPResponseTest extends TestCase
{
    /**
     * 测试基本构造函数
     */
    public function testConstruct(): void
    {
        $response = new OCSPResponse(OCSPResponse::SUCCESSFUL, 'raw-data');
        
        $this->assertEquals(OCSPResponse::SUCCESSFUL, $response->getResponseStatus());
        $this->assertTrue($response->isSuccessful());
    }
    
    /**
     * 测试从DER数据解析OCSP响应
     */
    public function testFromDER(): void
    {
        // 使用模拟数据测试解析功能
        $mockParser = $this->getMockBuilder('\Tourze\TLSCertificate\Revocation\OCSP\OCSPResponseParser')
            ->disableOriginalConstructor()
            ->onlyMethods(['parse'])
            ->getMock();
            
        $responseData = [
            'responseStatus' => OCSPResponse::SUCCESSFUL,
            'producedAt' => new DateTimeImmutable(),
            'thisUpdate' => new DateTimeImmutable(),
            'nextUpdate' => new DateTimeImmutable('+1 day'),
            'certStatus' => OCSPResponse::CERT_STATUS_GOOD,
            'nonce' => 'test-nonce',
            'signatureAlgorithm' => 'sha256WithRSAEncryption',
            'signature' => 'test-signature',
            'responderID' => 'CN=OCSP Responder',
            'serialNumber' => '12345678',
            'certs' => []
        ];
        
        $mockParser->method('parse')
            ->willReturn($responseData);
            
        // 使用反射将解析器注入到OCSPResponse类中
        $reflection = new \ReflectionClass(OCSPResponse::class);
        $fromDERMethod = $reflection->getMethod('fromDER');
        $fromDERMethod->setAccessible(true);
        
        // 手动调用fromDER方法，传入模拟解析器
        $response = $fromDERMethod->invokeArgs(null, ['mock-der-data', $mockParser]);
        
        // 验证解析结果
        $this->assertEquals(OCSPResponse::SUCCESSFUL, $response->getResponseStatus());
        $this->assertTrue($response->isSuccessful());
        $this->assertNotNull($response->getProducedAt());
        $this->assertNotNull($response->getThisUpdate());
        $this->assertNotNull($response->getNextUpdate());
        $this->assertEquals('test-nonce', $response->getNonce());
        $this->assertEquals('sha256WithRSAEncryption', $response->getSignatureAlgorithm());
        $this->assertEquals('test-signature', $response->getSignature());
        $this->assertEquals('CN=OCSP Responder', $response->getResponderID());
        $this->assertEquals('12345678', $response->getSerialNumber());
    }
    
    /**
     * 测试从DER数据解析OCSP响应异常
     */
    public function testFromDERException(): void
    {
        // 创建一个会抛出异常的模拟解析器
        $mockParser = $this->getMockBuilder('\Tourze\TLSCertificate\Revocation\OCSP\OCSPResponseParser')
            ->disableOriginalConstructor()
            ->onlyMethods(['parse'])
            ->getMock();
            
        $mockParser->method('parse')
            ->willThrowException(new \Exception('解析错误'));
            
        // 使用反射将解析器注入到OCSPResponse类中
        $reflection = new \ReflectionClass(OCSPResponse::class);
        $fromDERMethod = $reflection->getMethod('fromDER');
        $fromDERMethod->setAccessible(true);
        
        // 预期从DER方法会抛出OCSPException
        $this->expectException(OCSPException::class);
        
        // 手动调用fromDER方法，传入模拟解析器
        $fromDERMethod->invokeArgs(null, ['invalid-der-data', $mockParser]);
    }
    
    /**
     * 测试OCSP响应状态文本
     */
    public function testResponseStatusText(): void
    {
        // 测试各种响应状态的文本
        $response1 = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        $this->assertEquals('成功', $response1->getResponseStatusText());
        
        $response2 = new OCSPResponse(OCSPResponse::MALFORMED_REQUEST);
        $this->assertEquals('格式错误的请求', $response2->getResponseStatusText());
        
        $response3 = new OCSPResponse(OCSPResponse::INTERNAL_ERROR);
        $this->assertEquals('内部错误', $response3->getResponseStatusText());
        
        $response4 = new OCSPResponse(OCSPResponse::TRY_LATER);
        $this->assertEquals('稍后重试', $response4->getResponseStatusText());
        
        $response5 = new OCSPResponse(OCSPResponse::SIG_REQUIRED);
        $this->assertEquals('需要签名', $response5->getResponseStatusText());
        
        $response6 = new OCSPResponse(OCSPResponse::UNAUTHORIZED);
        $this->assertEquals('未授权', $response6->getResponseStatusText());
        
        // 测试未知状态
        $response7 = new OCSPResponse(99);
        $this->assertStringContainsString('未知状态', $response7->getResponseStatusText());
    }
    
    /**
     * 测试证书状态方法
     */
    public function testCertificateStatus(): void
    {
        // 创建一个"良好"状态的响应
        $goodResponse = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        
        // 使用反射设置certStatus属性
        $reflection = new \ReflectionClass(OCSPResponse::class);
        $statusProperty = $reflection->getProperty('certStatus');
        $statusProperty->setAccessible(true);
        $statusProperty->setValue($goodResponse, OCSPResponse::CERT_STATUS_GOOD);
        
        // 验证证书状态
        $this->assertEquals(OCSPResponse::CERT_STATUS_GOOD, $goodResponse->getCertStatus());
        $this->assertEquals('有效', $goodResponse->getCertStatusText());
        $this->assertTrue($goodResponse->isCertificateGood());
        $this->assertFalse($goodResponse->isCertificateRevoked());
        $this->assertFalse($goodResponse->isCertificateUnknown());
        
        // 创建一个"已撤销"状态的响应
        $revokedResponse = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        
        // 设置撤销状态
        $statusProperty->setValue($revokedResponse, OCSPResponse::CERT_STATUS_REVOKED);
        
        // 设置撤销时间和原因
        $revocationTimeProperty = $reflection->getProperty('revocationTime');
        $revocationTimeProperty->setAccessible(true);
        $revocationTimeProperty->setValue($revokedResponse, new DateTimeImmutable());
        
        $revocationReasonProperty = $reflection->getProperty('revocationReason');
        $revocationReasonProperty->setAccessible(true);
        $revocationReasonProperty->setValue($revokedResponse, 1); // 密钥泄露
        
        // 验证撤销状态
        $this->assertEquals(OCSPResponse::CERT_STATUS_REVOKED, $revokedResponse->getCertStatus());
        $this->assertEquals('已撤销', $revokedResponse->getCertStatusText());
        $this->assertFalse($revokedResponse->isCertificateGood());
        $this->assertTrue($revokedResponse->isCertificateRevoked());
        $this->assertFalse($revokedResponse->isCertificateUnknown());
        $this->assertNotNull($revokedResponse->getRevocationTime());
        $this->assertEquals(1, $revokedResponse->getRevocationReason());
        
        // 创建一个"未知"状态的响应
        $unknownResponse = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        
        // 设置未知状态
        $statusProperty->setValue($unknownResponse, OCSPResponse::CERT_STATUS_UNKNOWN);
        
        // 验证未知状态
        $this->assertEquals(OCSPResponse::CERT_STATUS_UNKNOWN, $unknownResponse->getCertStatus());
        $this->assertEquals('未知', $unknownResponse->getCertStatusText());
        $this->assertFalse($unknownResponse->isCertificateGood());
        $this->assertFalse($unknownResponse->isCertificateRevoked());
        $this->assertTrue($unknownResponse->isCertificateUnknown());
    }
    
    /**
     * 测试随机数验证
     */
    public function testNonceVerification(): void
    {
        // 创建一个基本响应
        $response = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        
        // 使用反射设置nonce
        $reflection = new \ReflectionClass(OCSPResponse::class);
        $property = $reflection->getProperty('nonce');
        $property->setAccessible(true);
        $property->setValue($response, 'test-nonce-123');
        
        // 验证随机数
        $this->assertTrue($response->verifyNonce('test-nonce-123'));
        $this->assertFalse($response->verifyNonce('wrong-nonce'));
        
        // 创建一个请求对象
        $request = new OCSPRequest('123456', 'issuer-hash', 'key-hash', 'sha1', 'test-nonce-123');
        
        // 验证请求的随机数
        $this->assertTrue($response->verifyNonce($request->getNonce()));
    }
    
    /**
     * 测试过期检查
     */
    public function testExpiryCheck(): void
    {
        // 创建一个过期的响应
        $expiredResponse = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        
        // 使用反射设置nextUpdate为过去时间
        $reflection = new \ReflectionClass(OCSPResponse::class);
        $property = $reflection->getProperty('nextUpdate');
        $property->setAccessible(true);
        $property->setValue($expiredResponse, new DateTimeImmutable('-1 day'));
        
        // 验证已过期
        $this->assertTrue($expiredResponse->isExpired());
        
        // 创建一个未过期的响应
        $validResponse = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        
        // 设置nextUpdate为未来时间
        $property->setValue($validResponse, new DateTimeImmutable('+1 day'));
        
        // 验证未过期
        $this->assertFalse($validResponse->isExpired());
        
        // 创建一个即将过期的响应
        $expiringResponse = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        
        // 设置nextUpdate为很短时间后（600秒 = 10分钟）
        $property->setValue($expiringResponse, new DateTimeImmutable('+600 seconds'));
        
        // 设置expiryWarningDays属性（改为以秒为单位）
        $expiryWarningDaysProperty = $reflection->getProperty('expiryWarningDays');
        $expiryWarningDaysProperty->setAccessible(true);
        $expiryWarningDaysProperty->setValue($expiringResponse, 3600); // 3600秒 = 1小时
        
        // 验证即将过期（由于nextUpdate在当前时间和警告阈值之间）
        $this->assertTrue($expiringResponse->isExpiringSoon());
        
        // 使用不同的阈值测试
        $this->assertFalse($expiringResponse->isExpiringSoon(5)); // 5秒（小于10分钟）
        $this->assertTrue($expiringResponse->isExpiringSoon(900)); // 900秒 = 15分钟（大于10分钟）
    }
    
    /**
     * 测试OCSP响应签名验证
     */
    public function testSignatureVerification(): void
    {
        // 创建一个响应
        $response = new OCSPResponse(OCSPResponse::SUCCESSFUL, 'raw-data');
        
        // 使用反射设置签名相关属性
        $reflection = new \ReflectionClass(OCSPResponse::class);
        
        $signatureProperty = $reflection->getProperty('signature');
        $signatureProperty->setAccessible(true);
        $signatureProperty->setValue($response, 'test-signature');
        
        $signatureAlgorithmProperty = $reflection->getProperty('signatureAlgorithm');
        $signatureAlgorithmProperty->setAccessible(true);
        $signatureAlgorithmProperty->setValue($response, 'sha256WithRSAEncryption');
        
        $tbsProperty = $reflection->getProperty('tbsResponseData');
        $tbsProperty->setAccessible(true);
        $tbsProperty->setValue($response, ['key' => 'value']);
        
        // 创建模拟证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getPublicKey')->willReturn('public-key');
        
        // 创建模拟签名验证器
        $mockVerifier = $this->createMock(SignatureVerifier::class);
        $mockVerifier->method('verify')
            ->with(
                $this->isType('string'),
                $this->equalTo('test-signature'),
                $this->equalTo('public-key'),
                $this->equalTo('sha256WithRSAEncryption')
            )
            ->willReturn(true);
        
        // 验证签名
        $this->assertTrue($response->verifySignature($mockCertificate, $mockVerifier));
        
        // 测试签名验证失败
        $mockFailedVerifier = $this->createMock(SignatureVerifier::class);
        $mockFailedVerifier->method('verify')->willReturn(false);
        
        $this->assertFalse($response->verifySignature($mockCertificate, $mockFailedVerifier));
    }
    
    /**
     * 测试检查响应是否匹配请求
     */
    public function testMatchRequest(): void
    {
        // 创建响应
        $response = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        
        // 使用反射设置响应的序列号和颁发者信息
        $reflection = new \ReflectionClass(OCSPResponse::class);
        
        $serialProperty = $reflection->getProperty('serialNumber');
        $serialProperty->setAccessible(true);
        $serialProperty->setValue($response, '1234567890');
        
        $issuerNameHashProperty = $reflection->getProperty('issuerNameHash');
        $issuerNameHashProperty->setAccessible(true);
        $issuerNameHashProperty->setValue($response, 'abcdef1234567890');
        
        $issuerKeyHashProperty = $reflection->getProperty('issuerKeyHash');
        $issuerKeyHashProperty->setAccessible(true);
        $issuerKeyHashProperty->setValue($response, '0987654321fedcba');
        
        // 创建匹配的请求
        $matchingRequest = new OCSPRequest(
            '1234567890',
            'abcdef1234567890',
            '0987654321fedcba',
            'sha256',
            'randomnonce123'
        );
        
        // 创建不匹配的请求
        $nonMatchingRequest = new OCSPRequest(
            '9876543210', // 不同的序列号
            'abcdef1234567890',
            '0987654321fedcba',
            'sha256',
            'randomnonce123'
        );
        
        // 验证匹配和不匹配
        $this->assertTrue($response->matchesRequest($matchingRequest));
        $this->assertFalse($response->matchesRequest($nonMatchingRequest));
    }
} 