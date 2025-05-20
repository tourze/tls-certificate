<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Parser;

use Tourze\TLSCertificate\Certificate\X509Certificate;
use Tourze\TLSCertificate\Exception\ParserException;
use Tourze\TLSCertificate\Extractor\CertificateFieldExtractor;

/**
 * 证书解析器
 * 
 * 负责解析不同格式的X.509证书
 */
class CertificateParser
{
    /**
     * 证书字段提取器
     */
    private CertificateFieldExtractor $extractor;
    
    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->extractor = new CertificateFieldExtractor();
    }
    
    /**
     * 解析PEM格式证书
     *
     * @param string $pemData PEM格式的证书数据
     * @return X509Certificate 解析后的证书对象
     * @throws ParserException 如果解析失败
     */
    public function parsePEM(string $pemData): X509Certificate
    {
        // 验证PEM格式
        if (!preg_match('/-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----/s', $pemData)) {
            throw new ParserException('无效的PEM格式证书');
        }
        
        // 转换为DER格式
        $derData = $this->pemToDer($pemData);
        
        // 解析DER格式数据
        return $this->parseDER($derData);
    }
    
    /**
     * 解析DER格式证书
     *
     * @param string $derData DER格式的证书数据
     * @return X509Certificate 解析后的证书对象
     * @throws ParserException 如果解析失败
     */
    public function parseDER(string $derData): X509Certificate
    {
        try {
            // 这里应该使用ASN.1解析库解析DER数据
            // 为了简化示例，我们假设已经解析成功并得到证书数据
            // 实际实现需要集成一个ASN.1解析库
            
            // 模拟ASN.1解析结果
            $asn1Data = $this->mockAsn1Parse($derData);
            
            // 创建证书对象
            $certificate = new X509Certificate();
            
            // 提取证书字段
            $this->extractor->extractFields($asn1Data, $certificate);
            
            return $certificate;
        } catch (\Exception $e) {
            throw new ParserException('解析DER格式证书失败: ' . $e->getMessage(), 0, $e);
        }
    }
    
    /**
     * 将PEM格式转换为DER格式
     *
     * @param string $pemData PEM格式的证书数据
     * @return string DER格式的证书数据
     * @throws ParserException 如果转换失败
     */
    public function pemToDer(string $pemData): string
    {
        // 删除PEM头尾和所有换行符
        $pattern = '/-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----/s';
        if (!preg_match($pattern, $pemData, $matches)) {
            throw new ParserException('无效的PEM格式证书');
        }
        
        // 获取Base64编码的证书数据
        $base64Data = $matches[1];
        $base64Data = preg_replace('/\s+/', '', $base64Data);
        
        // 解码Base64数据
        $derData = base64_decode($base64Data, true);
        if ($derData === false) {
            throw new ParserException('证书Base64解码失败');
        }
        
        return $derData;
    }
    
    /**
     * 将DER格式转换为PEM格式
     *
     * @param string $derData DER格式的证书数据
     * @return string PEM格式的证书数据
     */
    public function derToPem(string $derData): string
    {
        // Base64编码DER数据
        $base64Data = base64_encode($derData);
        
        // 每64个字符插入一个换行符
        $base64Data = chunk_split($base64Data, 64, "\n");
        
        // 添加PEM头尾
        return "-----BEGIN CERTIFICATE-----\n" . $base64Data . "-----END CERTIFICATE-----\n";
    }
    
    /**
     * 模拟ASN.1解析
     * 
     * 注意：这只是一个模拟实现，实际项目中应该使用专门的ASN.1解析库
     *
     * @param string $derData DER格式的证书数据
     * @return array 解析后的ASN.1结构
     */
    private function mockAsn1Parse(string $derData): array
    {
        // 这是一个模拟实现，实际项目应该使用ASN.1解析库
        // 在这里，我们根据PEM证书的常见结构返回一个模拟的数据结构
        
        // 为了测试，简单地从DER数据的头8字节生成一个序列号
        $serialNumber = bin2hex(substr($derData, 0, 8));
        
        // 假设这是一个X.509v3证书
        return [
            'tbsCertificate' => [
                'version' => 2, // X.509v3
                'serialNumber' => $serialNumber,
                'signature' => [
                    'algorithm' => 'sha256WithRSAEncryption',
                ],
                'issuer' => [
                    'rdnSequence' => [
                        [['type' => '2.5.4.3', 'value' => 'Test CA']], // CN
                        [['type' => '2.5.4.10', 'value' => 'Internet Widgits Pty Ltd']], // O
                    ],
                ],
                'validity' => [
                    'notBefore' => '220101000000Z', // 2022-01-01 00:00:00 UTC
                    'notAfter' => '230101000000Z', // 2023-01-01 00:00:00 UTC
                ],
                'subject' => [
                    'rdnSequence' => [
                        [['type' => '2.5.4.3', 'value' => 'example.com']], // CN
                        [['type' => '2.5.4.10', 'value' => 'Internet Widgits Pty Ltd']], // O
                    ],
                ],
                'subjectPublicKeyInfo' => [
                    'algorithm' => [
                        'algorithm' => '1.2.840.113549.1.1.1', // RSA
                    ],
                    'subjectPublicKey' => substr($derData, -64), // 简单地使用DER数据的最后部分作为公钥
                ],
            ],
            'signatureAlgorithm' => [
                'algorithm' => 'sha256WithRSAEncryption',
            ],
            'signature' => 'SIGNATURE_DATA',
        ];
    }
}
