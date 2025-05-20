<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Certificate;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\X509Certificate;

/**
 * X.509证书类的单元测试
 */
class X509CertificateTest extends TestCase
{
    /**
     * 测试创建X509证书实例并获取扩展属性
     */
    public function testCreateCertificateAndGetExtensions(): void
    {
        $certificate = new X509Certificate();
        
        // 测试默认扩展属性
        $this->assertNull($certificate->getExtensions());
        $this->assertNull($certificate->getSignature());
        $this->assertNull($certificate->getCRLDistributionPoints());
        $this->assertNull($certificate->getOCSPResponderUrl());
    }
    
    /**
     * 测试设置和获取X509证书扩展属性
     */
    public function testSetAndGetExtensionProperties(): void
    {
        $certificate = new X509Certificate();
        
        // 设置扩展属性
        $extensions = [
            '2.5.29.15' => ['digitalSignature', 'keyEncipherment'], // Key Usage
            '2.5.29.17' => ['DNS:example.com', 'IP:192.168.1.1'],  // Subject Alternative Name
        ];
        $signature = 'DUMMY_SIGNATURE_DATA';
        $crlPoints = ['http://example.com/crl.pem'];
        $ocspUrl = 'http://ocsp.example.com';
        
        $certificate->setExtensions($extensions);
        $certificate->setSignature($signature);
        $certificate->setCRLDistributionPoints($crlPoints);
        $certificate->setOCSPResponderUrl($ocspUrl);
        
        // 验证属性是否正确设置
        $this->assertSame($extensions, $certificate->getExtensions());
        $this->assertSame($signature, $certificate->getSignature());
        $this->assertSame($crlPoints, $certificate->getCRLDistributionPoints());
        $this->assertSame($ocspUrl, $certificate->getOCSPResponderUrl());
    }
    
    /**
     * 测试扩展访问方法
     */
    public function testExtensionAccessMethods(): void
    {
        $certificate = new X509Certificate();
        
        // 测试空扩展
        $this->assertFalse($certificate->hasExtension('2.5.29.15'));
        $this->assertNull($certificate->getExtension('2.5.29.15'));
        
        // 设置扩展
        $extensions = [
            '2.5.29.15' => ['digitalSignature', 'keyEncipherment'], // Key Usage
            '2.5.29.17' => ['DNS:example.com', 'IP:192.168.1.1'],  // Subject Alternative Name
        ];
        
        $certificate->setExtensions($extensions);
        
        // 测试扩展访问
        $this->assertTrue($certificate->hasExtension('2.5.29.15'));
        $this->assertTrue($certificate->hasExtension('2.5.29.17'));
        $this->assertFalse($certificate->hasExtension('2.5.29.19')); // Basic Constraints
        
        $this->assertSame(['digitalSignature', 'keyEncipherment'], $certificate->getExtension('2.5.29.15'));
        $this->assertSame(['DNS:example.com', 'IP:192.168.1.1'], $certificate->getExtension('2.5.29.17'));
        $this->assertNull($certificate->getExtension('2.5.29.19'));
    }
    
    /**
     * 测试继承自Certificate类的方法
     */
    public function testInheritedMethods(): void
    {
        $certificate = new X509Certificate();
        
        // 测试基本Certificate类方法
        $certificate->setVersion(3);
        $this->assertSame(3, $certificate->getVersion());
        
        $now = new \DateTimeImmutable();
        $future = $now->modify('+1 year');
        
        $certificate->setNotBefore($now);
        $certificate->setNotAfter($future);
        
        $this->assertTrue($certificate->isValid());
    }
} 