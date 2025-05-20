<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Certificate;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\Certificate;
use Tourze\TLSCertificate\Exception\CertificateException;

/**
 * 通用证书类的单元测试
 */
class CertificateTest extends TestCase
{
    /**
     * 测试创建证书实例并获取基本属性
     */
    public function testCreateCertificateAndGetBasicProperties(): void
    {
        $certificate = new Certificate();
        
        // 测试默认属性
        $this->assertNull($certificate->getVersion());
        $this->assertNull($certificate->getSerialNumber());
        $this->assertNull($certificate->getSignatureAlgorithm());
        $this->assertNull($certificate->getIssuer());
        $this->assertNull($certificate->getSubject());
        $this->assertNull($certificate->getNotBefore());
        $this->assertNull($certificate->getNotAfter());
        $this->assertNull($certificate->getPublicKey());
        $this->assertFalse($certificate->isValid());
    }
    
    /**
     * 测试设置和获取证书属性
     */
    public function testSetAndGetProperties(): void
    {
        $certificate = new Certificate();
        
        // 设置基本属性
        $now = new \DateTimeImmutable();
        $future = $now->modify('+1 year');
        
        $certificate->setVersion(3);
        $certificate->setSerialNumber('1234567890');
        $certificate->setSignatureAlgorithm('sha256WithRSAEncryption');
        $certificate->setIssuer(['CN' => 'Test CA']);
        $certificate->setSubject(['CN' => 'example.com']);
        $certificate->setNotBefore($now);
        $certificate->setNotAfter($future);
        $certificate->setPublicKey('DUMMY_PUBLIC_KEY');
        
        // 验证属性是否正确设置
        $this->assertSame(3, $certificate->getVersion());
        $this->assertSame('1234567890', $certificate->getSerialNumber());
        $this->assertSame('sha256WithRSAEncryption', $certificate->getSignatureAlgorithm());
        $this->assertSame(['CN' => 'Test CA'], $certificate->getIssuer());
        $this->assertSame(['CN' => 'example.com'], $certificate->getSubject());
        $this->assertSame($now, $certificate->getNotBefore());
        $this->assertSame($future, $certificate->getNotAfter());
        $this->assertSame('DUMMY_PUBLIC_KEY', $certificate->getPublicKey());
    }
    
    /**
     * 测试证书有效期验证
     */
    public function testValidityPeriod(): void
    {
        $certificate = new Certificate();
        
        // 设置过期的证书
        $pastStart = new \DateTimeImmutable('-2 years');
        $pastEnd = new \DateTimeImmutable('-1 year');
        
        $certificate->setNotBefore($pastStart);
        $certificate->setNotAfter($pastEnd);
        
        $this->assertFalse($certificate->isValid());
        
        // 设置有效的证书
        $now = new \DateTimeImmutable();
        $future = $now->modify('+1 year');
        
        $certificate->setNotBefore($now);
        $certificate->setNotAfter($future);
        
        $this->assertTrue($certificate->isValid());
        
        // 设置未来的证书
        $futureStart = new \DateTimeImmutable('+1 day');
        $futureEnd = new \DateTimeImmutable('+2 years');
        
        $certificate->setNotBefore($futureStart);
        $certificate->setNotAfter($futureEnd);
        
        $this->assertFalse($certificate->isValid());
    }
    
    /**
     * 测试错误处理
     */
    public function testExceptionHandling(): void
    {
        $certificate = new Certificate();
        
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('无效的证书版本');
        
        $certificate->setVersion(-1);
    }
} 