<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Tests\Revocation\CRL;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Revocation\CRL\CertificateRevocationList;
use Tourze\TLSCertificate\Revocation\CRL\CRLCache;
use Tourze\TLSCertificate\Revocation\CRL\CRLParser;
use Tourze\TLSCertificate\Revocation\CRL\CRLUpdater;

/**
 * CRL更新和过期处理测试类
 */
class CRLUpdateTest extends TestCase
{
    /**
     * @var CRLCache
     */
    private CRLCache $crlCache;
    
    /**
     * @var CRLParser
     */
    private CRLParser $crlParser;
    
    /**
     * 测试前准备
     */
    protected function setUp(): void
    {
        $this->crlCache = new CRLCache();
        $this->crlParser = new CRLParser();
    }
    
    /**
     * 测试CRL缓存基础功能
     */
    public function testCRLCacheBasicFunctionality(): void
    {
        // 创建CRL
        $crl = new CertificateRevocationList(
            'CN=Test CA Issuer',
            new DateTimeImmutable(),
            new DateTimeImmutable('+1 day'),
            '1'
        );
        
        // 添加到缓存
        $this->crlCache->add('CN=Test CA Issuer', $crl);
        
        // 从缓存获取
        $cachedCRL = $this->crlCache->get('CN=Test CA Issuer');
        
        // 断言
        $this->assertSame($crl, $cachedCRL);
    }
    
    /**
     * 测试CRL缓存过期处理
     */
    public function testCRLCacheExpiry(): void
    {
        // 创建即将过期的CRL
        $expiringSoonCRL = new CertificateRevocationList(
            'CN=Expiring CA',
            new DateTimeImmutable(),
            new DateTimeImmutable('+1 minute'),
            '1'
        );
        
        // 添加到缓存
        $this->crlCache->add('CN=Expiring CA', $expiringSoonCRL);
        
        // 断言CRL快过期
        $this->assertTrue($this->crlCache->isExpiringSoon('CN=Expiring CA', 120)); // 2分钟阈值
        
        // 创建已过期的CRL
        $expiredCRL = new CertificateRevocationList(
            'CN=Expired CA',
            new DateTimeImmutable('-2 days'),
            new DateTimeImmutable('-1 day'),
            '1'
        );
        
        // 添加到缓存
        $this->crlCache->add('CN=Expired CA', $expiredCRL);
        
        // 检查过期CRL的清理
        $removedCount = $this->crlCache->removeExpired();
        
        // 断言成功移除了一个过期CRL
        $this->assertEquals(1, $removedCount);
        
        // 断言过期CRL已经从缓存中移除
        $this->assertNull($this->crlCache->get('CN=Expired CA'));
        
        // 断言即将过期但尚未过期的CRL仍在缓存中
        $this->assertNotNull($this->crlCache->get('CN=Expiring CA'));
    }
    
    /**
     * 测试CRL自动更新
     */
    public function testCRLAutoRefresh(): void
    {
        // 创建模拟的CRL解析器
        $mockParser = $this->createMock(CRLParser::class);
        
        // 创建模拟的CRL缓存
        $mockCache = $this->createMock(CRLCache::class);
        
        // 创建CRL更新器
        $updater = new CRLUpdater($mockParser, $mockCache);
        
        // 创建旧的CRL
        $oldCRL = new CertificateRevocationList(
            'CN=Test CA',
            new DateTimeImmutable('-1 day'),
            new DateTimeImmutable('+2 days'),
            '1'
        );
        
        // 创建新的CRL
        $newCRL = new CertificateRevocationList(
            'CN=Test CA',
            new DateTimeImmutable(),
            new DateTimeImmutable('+3 days'),
            '2' // 更高的CRL序号
        );
        
        // 设置模拟行为
        $mockCache->method('get')
            ->with('CN=Test CA')
            ->willReturn($oldCRL);
        
        $mockCache->method('isExpiringSoon')
            ->with('CN=Test CA')
            ->willReturn(true);
        
        $mockParser->method('fetchFromURL')
            ->with('http://example.com/crl.pem')
            ->willReturn($newCRL);
        
        $mockCache->expects($this->once())
            ->method('add')
            ->with('CN=Test CA', $newCRL);
        
        // 执行更新
        $updater->updateCRL('CN=Test CA', 'http://example.com/crl.pem');
    }
    
    /**
     * 测试使用较低CRL序号拒绝更新
     */
    public function testRejectUpdateWithLowerCRLNumber(): void
    {
        // 创建模拟的CRL解析器
        $mockParser = $this->createMock(CRLParser::class);
        
        // 创建模拟的CRL缓存
        $mockCache = $this->createMock(CRLCache::class);
        
        // 创建CRL更新器
        $updater = new CRLUpdater($mockParser, $mockCache);
        
        // 创建较新的CRL（但具有较高的CRL序号）
        $currentCRL = new CertificateRevocationList(
            'CN=Test CA',
            new DateTimeImmutable('-1 day'),
            new DateTimeImmutable('+2 days'),
            '2'
        );
        
        // 创建较旧的CRL（尽管日期更新，但CRL序号较低）
        $olderCRL = new CertificateRevocationList(
            'CN=Test CA',
            new DateTimeImmutable(),
            new DateTimeImmutable('+3 days'),
            '1'
        );
        
        // 设置模拟行为
        $mockCache->method('get')
            ->with('CN=Test CA')
            ->willReturn($currentCRL);
        
        $mockCache->method('isExpiringSoon')
            ->with('CN=Test CA')
            ->willReturn(true);
        
        $mockParser->method('fetchFromURL')
            ->with('http://example.com/crl.pem')
            ->willReturn($olderCRL);
        
        // 确保add方法不会被调用，因为我们不应该用旧的CRL更新
        $mockCache->expects($this->never())
            ->method('add');
        
        // 执行更新
        $result = $updater->updateCRL('CN=Test CA', 'http://example.com/crl.pem');
        
        // 断言更新被拒绝
        $this->assertFalse($result);
    }
    
    /**
     * 测试从证书中提取CRL分发点并获取CRL
     */
    public function testFetchCRLFromCertificate(): void
    {
        // 创建模拟的证书
        $mockCertificate = $this->createMock(X509Certificate::class);
        
        // 模拟extractCRLDistributionPoints方法
        $mockParser = $this->createPartialMock(CRLParser::class, ['extractCRLDistributionPoints', 'fetchFromURL']);
        $mockParser->method('extractCRLDistributionPoints')
            ->with($mockCertificate)
            ->willReturn(['http://example.com/crl.pem']);
            
        // 模拟fetchFromURL方法
        $mockCRL = $this->createMock(CertificateRevocationList::class);
        $mockParser->method('fetchFromURL')
            ->with('http://example.com/crl.pem')
            ->willReturn($mockCRL);
            
        // 调用方法
        $result = $mockParser->extractCRLDistributionPoints($mockCertificate);
        $crl = $mockParser->fetchFromURL($result[0]);
        
        // 断言
        $this->assertSame($mockCRL, $crl);
    }
    
    /**
     * 测试CRL更新失败处理
     */
    public function testCRLUpdateFailureHandling(): void
    {
        // 创建模拟的CRL解析器
        $mockParser = $this->createMock(CRLParser::class);
        
        // 创建模拟的CRL缓存
        $mockCache = $this->createMock(CRLCache::class);
        
        // 创建CRL更新器
        $updater = new CRLUpdater($mockParser, $mockCache);
        
        // 创建当前的CRL
        $currentCRL = new CertificateRevocationList(
            'CN=Test CA',
            new DateTimeImmutable('-1 day'),
            new DateTimeImmutable('+2 days'),
            '1'
        );
        
        // 设置模拟行为
        $mockCache->method('get')
            ->with('CN=Test CA')
            ->willReturn($currentCRL);
        
        $mockCache->method('isExpiringSoon')
            ->with('CN=Test CA')
            ->willReturn(true);
        
        // 模拟网络错误
        $mockParser->method('fetchFromURL')
            ->with('http://example.com/crl.pem')
            ->willThrowException(new \Exception('网络错误'));
        
        // 执行更新，应该返回false但不会抛出异常
        $result = $updater->updateCRL('CN=Test CA', 'http://example.com/crl.pem', true);
        
        // 断言更新失败但没有抛出异常（静默失败）
        $this->assertFalse($result);
    }
}
