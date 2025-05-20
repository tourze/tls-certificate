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
        // 创建模拟的证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willReturn('1234567890');
        
        // 创建模拟的颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        
        // 模拟getSubjectDNDER方法，返回DER编码的主题
        $mockIssuerCertificate->method('getSubjectDNDER')
            ->willReturn('der-encoded-subject');
        
        // 模拟getPublicKeyDER方法
        $mockIssuerCertificate->method('getPublicKeyDER')
            ->willReturn('test-public-key-data');
        
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
        
        // 模拟OCSPRequest中的私有_encodeRequest方法
        $mockRequest = $this->getMockBuilder(OCSPRequest::class)
            ->setConstructorArgs(['1234567890', 'abcdef1234567890', '0987654321fedcba', 'sha256', 'randomnonce123'])
            ->onlyMethods(['_encodeRequest'])
            ->getMock();
            
        $mockRequest->method('_encodeRequest')
            ->willReturn('encoded-ocsp-request-data');
        
        // 断言编码结果
        $encoded = $mockRequest->encode();
        $this->assertEquals('encoded-ocsp-request-data', $encoded);
        
        // 断言多次调用返回相同结果（缓存）
        $this->assertSame($encoded, $mockRequest->encode());
    }
    
    /**
     * 测试OCSP请求HTTP编码
     */
    public function testEncodeForHTTP(): void
    {
        $request = $this->getMockBuilder(OCSPRequest::class)
            ->setConstructorArgs(['1234567890', 'abcdef1234567890', '0987654321fedcba', 'sha256', 'randomnonce123'])
            ->onlyMethods(['encode'])
            ->getMock();
            
        $request->method('encode')
            ->willReturn('raw-encoded-data');
        
        // 编码为HTTP请求主体
        $httpBody = $request->encodeForHTTP();
        
        // 断言结果是Base64编码
        $this->assertIsString($httpBody);
        $this->assertEquals(base64_encode('raw-encoded-data'), $httpBody);
    }
    
    /**
     * 测试使用OpenSSL的OCSP请求生成
     */
    public function testGenerateOCSPRequestWithOpenSSL(): void
    {
        // 创建模拟的证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willReturn('1234567890');
        $mockCertificate->method('toPEM')->willReturn('-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJyPejb0gWvEMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n-----END CERTIFICATE-----');
        
        // 创建模拟的颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        $mockIssuerCertificate->method('toPEM')->willReturn('-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAPO9ZhuQ0cmgMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n-----END CERTIFICATE-----');
        
        // 添加必要的方法模拟
        $mockIssuerCertificate->method('getSubjectDNDER')->willReturn('der-encoded-subject');
        $mockIssuerCertificate->method('getPublicKeyDER')->willReturn('test-public-key-data');
        
        // 使用模拟的静态方法代替实际调用
        $mockRequest = $this->getMockBuilder(OCSPRequest::class)
            ->disableOriginalConstructor()
            ->getMock();
        
        // 使用反射来模拟静态方法调用
        $reflectionClass = new \ReflectionClass(OCSPRequest::class);
        $fromCertificateMethod = $reflectionClass->getMethod('fromCertificate');
        
        // 测试实际的方法调用，但使用模拟的证书对象
        $result = $fromCertificateMethod->invoke(null, $mockCertificate, $mockIssuerCertificate, 'sha1', true);
        
        // 断言
        $this->assertInstanceOf(OCSPRequest::class, $result);
    }
    
    /**
     * 测试从证书创建OCSP请求异常
     */
    public function testFromCertificateException(): void
    {
        $this->expectException(OCSPException::class);
        
        // 创建模拟的证书，抛出异常
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getSerialNumber')->willThrowException(new \Exception('测试异常'));
        
        // 创建模拟的颁发者证书
        $mockIssuerCertificate = $this->createMock(X509Certificate::class);
        
        // 预期抛出OCSPException
        OCSPRequest::fromCertificate($mockCertificate, $mockIssuerCertificate);
    }
    
    /**
     * 测试生成OCSP请求URL
     */
    public function testGetRequestURL(): void
    {
        // 创建带有OCSP URL和请求的测试对象
        $request = new OCSPRequest(
            '1234567890',
            'abcdef1234567890',
            '0987654321fedcba',
            'sha256',
            'randomnonce123'
        );
        
        // 模拟请求编码
        $mockRequest = $this->getMockBuilder(OCSPRequest::class)
            ->setConstructorArgs(['1234567890', 'abcdef1234567890', '0987654321fedcba', 'sha256', 'randomnonce123'])
            ->onlyMethods(['encodeForHTTP'])
            ->getMock();
            
        $mockRequest->method('encodeForHTTP')
            ->willReturn('base64encodedrequest');
        
        // 测试生成URL
        $url = $mockRequest->getRequestURL('http://ocsp.example.com');
        
        // 验证URL格式
        $this->assertStringStartsWith('http://ocsp.example.com/', $url);
        $this->assertStringContainsString('base64encodedrequest', $url);
    }
} 