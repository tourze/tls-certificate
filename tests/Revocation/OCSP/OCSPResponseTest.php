<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Revocation\OCSP;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
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
        // 注意：由于我们的fromDER方法目前是一个简化实现，这个测试只测试基本行为
        $response = OCSPResponse::fromDER('mock-der-data');
        
        $this->assertEquals(OCSPResponse::SUCCESSFUL, $response->getResponseStatus());
        $this->assertTrue($response->isSuccessful());
        $this->assertNotNull($response->getProducedAt());
        $this->assertNotNull($response->getThisUpdate());
        $this->assertNotNull($response->getNextUpdate());
    }
    
    /**
     * 测试从DER数据解析OCSP响应异常
     */
    public function testFromDERException(): void
    {
        // 模拟一个会导致异常的场景
        // 由于我们的实现目前不会抛出异常，这个测试实际上可能无法失败
        // 但包含它可以确保将来的更改会考虑这种情况
        
        $this->markTestSkipped('当前fromDER实现不会抛出异常，待完整实现后再测试');
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
        // 创建一个模拟的有效响应
        $goodResponse = OCSPResponse::fromDER('mock-der-data');
        // 默认实现返回CERT_STATUS_GOOD
        
        $this->assertEquals(OCSPResponse::CERT_STATUS_GOOD, $goodResponse->getCertStatus());
        $this->assertEquals('有效', $goodResponse->getCertStatusText());
        $this->assertTrue($goodResponse->isCertificateGood());
        $this->assertFalse($goodResponse->isCertificateRevoked());
        
        // 创建一个基本响应，手动设置certStatus属性为REVOKED
        // 由于certStatus是private的，我们需要使用反射来设置它
        $revokedResponse = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        $reflection = new \ReflectionClass(OCSPResponse::class);
        $property = $reflection->getProperty('certStatus');
        $property->setAccessible(true);
        $property->setValue($revokedResponse, OCSPResponse::CERT_STATUS_REVOKED);
        
        // 设置撤销时间
        $revocationTimeProperty = $reflection->getProperty('revocationTime');
        $revocationTimeProperty->setAccessible(true);
        $revocationTimeProperty->setValue($revokedResponse, new DateTimeImmutable());
        
        $this->assertEquals(OCSPResponse::CERT_STATUS_REVOKED, $revokedResponse->getCertStatus());
        $this->assertEquals('已撤销', $revokedResponse->getCertStatusText());
        $this->assertFalse($revokedResponse->isCertificateGood());
        $this->assertTrue($revokedResponse->isCertificateRevoked());
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
    }
} 