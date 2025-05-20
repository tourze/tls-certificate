<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Revocation\OCSP;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\OCSPException;
use Tourze\TLSCertificate\Revocation\OCSP\OCSPRequest;

/**
 * OCSPRequest测试类
 */
class OCSPRequestTest extends TestCase
{
    /**
     * 测试基本构造函数
     */
    public function testConstruct(): void
    {
        $request = new OCSPRequest(
            '1234567890',
            'abcdef1234567890',
            '0987654321fedcba',
            'sha256',
            'randomnonce123'
        );
        
        $this->assertEquals('1234567890', $request->getSerialNumber());
        $this->assertEquals('abcdef1234567890', $request->getIssuerNameHash());
        $this->assertEquals('0987654321fedcba', $request->getIssuerKeyHash());
        $this->assertEquals('sha256', $request->getHashAlgorithm());
        $this->assertEquals('randomnonce123', $request->getNonce());
    }
    
    /**
     * 测试从证书创建OCSP请求
     */
    public function testFromCertificate(): void
    {
        $this->markTestSkipped('OCSP功能尚未完全实现，详见开发文档');
        
        // 创建模拟的证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willReturn('1234567890');
        
        // 创建模拟的颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        $mockIssuerCertificate->method('getSubjectDN')->willReturn('CN=Test CA');
        $mockIssuerCertificate->method('getPublicKeyDER')->willReturn('test-public-key-data');
        
        // 当调用getSubjectDN(true)时，返回DER编码的主题
        $mockIssuerCertificate->method('getSubjectDN')
            ->with($this->equalTo(true))
            ->willReturn('der-encoded-subject');
        
        // 创建OCSP请求
        $request = OCSPRequest::fromCertificate($mockCertificate, $mockIssuerCertificate, 'sha1', true);
        
        // 断言
        $this->assertEquals('1234567890', $request->getSerialNumber());
        $this->assertNotEmpty($request->getIssuerNameHash());
        $this->assertNotEmpty($request->getIssuerKeyHash());
        $this->assertEquals('sha1', $request->getHashAlgorithm());
        $this->assertNotNull($request->getNonce());
    }
    
    /**
     * 测试OCSP请求编码
     */
    public function testEncode(): void
    {
        $request = new OCSPRequest(
            '1234567890',
            'abcdef1234567890',
            '0987654321fedcba',
            'sha256',
            'randomnonce123'
        );
        
        // 目前encode()方法是一个存根实现，所以这只是一个基本测试
        $encoded = $request->encode();
        
        // 断言返回值是字符串
        $this->assertIsString($encoded);
        
        // 断言多次调用返回相同结果（缓存）
        $this->assertSame($encoded, $request->encode());
    }
    
    /**
     * 测试从证书创建OCSP请求异常
     */
    public function testFromCertificateException(): void
    {
        $this->markTestSkipped('OCSP功能尚未完全实现，详见开发文档');
        
        $this->expectException(OCSPException::class);
        
        // 创建模拟的证书，抛出异常
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willThrowException(new \Exception('测试异常'));
        
        // 创建模拟的颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        
        // 预期抛出OCSPException
        OCSPRequest::fromCertificate($mockCertificate, $mockIssuerCertificate);
    }
} 