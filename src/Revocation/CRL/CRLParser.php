<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\CRL;

use DateTimeImmutable;
use Tourze\TLSCertificate\Exception\CRLException;

/**
 * CRL解析器 - 解析X.509证书撤销列表
 */
class CRLParser
{
    /**
     * 构造函数
     */
    public function __construct()
    {
    }
    
    /**
     * 解析PEM格式的CRL
     *
     * @param string $pemData PEM格式的CRL数据
     * @return CertificateRevocationList 解析后的CRL
     * @throws CRLException 如果解析失败
     */
    public function parsePEM(string $pemData): CertificateRevocationList
    {
        // 提取PEM数据
        if (!preg_match('/-+BEGIN X509 CRL-+(.+?)-+END X509 CRL-+/s', $pemData, $matches)) {
            throw CRLException::parseError('无效的PEM格式');
        }
        
        // 解码Base64数据
        $derData = base64_decode(trim($matches[1]), true);
        if ($derData === false) {
            throw CRLException::parseError('无效的Base64编码');
        }
        
        return $this->parseDER($derData);
    }
    
    /**
     * 解析DER格式的CRL
     *
     * @param string $derData DER格式的CRL数据
     * @return CertificateRevocationList 解析后的CRL
     * @throws CRLException 如果解析失败
     */
    public function parseDER(string $derData): CertificateRevocationList
    {
        try {
            // 使用OpenSSL解析CRL
            $crlInfo = [];
            
            // 将DER数据转换为临时文件以供OpenSSL使用
            $tempFile = tempnam(sys_get_temp_dir(), 'crl');
            if ($tempFile === false) {
                throw CRLException::parseError('创建临时文件失败');
            }
            
            try {
                file_put_contents($tempFile, $derData);
                
                // 使用openssl命令行工具解析CRL
                $command = 'openssl crl -inform DER -in ' . escapeshellarg($tempFile) . ' -noout -text';
                $output = [];
                $exitCode = 0;
                exec($command, $output, $exitCode);
                
                if ($exitCode !== 0) {
                    throw CRLException::parseError('OpenSSL命令执行失败');
                }
                
                // 解析输出以提取CRL信息
                $outputText = implode("\n", $output);
                
                // 提取颁发者
                if (preg_match('/Issuer:\s*(.+)$/m', $outputText, $matches)) {
                    $crlInfo['issuer'] = trim($matches[1]);
                }
                
                // 提取lastUpdate
                if (preg_match('/Last Update:\s*(.+)$/m', $outputText, $matches)) {
                    $crlInfo['lastUpdate'] = trim($matches[1]);
                }
                
                // 提取nextUpdate
                if (preg_match('/Next Update:\s*(.+)$/m', $outputText, $matches)) {
                    $crlInfo['nextUpdate'] = trim($matches[1]);
                }
                
                // 提取签名算法
                if (preg_match('/Signature Algorithm:\s*(.+)$/m', $outputText, $matches)) {
                    $crlInfo['signatureAlgorithm'] = trim($matches[1]);
                }
                
                // 提取CRL编号
                if (preg_match('/CRL Number:\s*(.+)$/m', $outputText, $matches)) {
                    $crlInfo['crlNumber'] = trim($matches[1]);
                }
                
                // 提取撤销证书列表
                $revokedCerts = [];
                if (preg_match_all('/Serial Number:\s*(.+?)[\r\n]+\s*Revocation Date:\s*(.+?)(?:[\r\n]+\s*CRL entry extensions:[^\r\n]*[\r\n]+\s*X509v3 CRL Reason Code:\s*(.+?))?(?=[\r\n]+\s*Serial Number:|$)/s', $outputText, $matches, PREG_SET_ORDER)) {
                    foreach ($matches as $match) {
                        $serialNumber = trim($match[1]);
                        $revocationDate = trim($match[2]);
                        $reasonCode = isset($match[3]) ? trim($match[3]) : null;
                        
                        $revokedCerts[] = [
                            'serialNumber' => $serialNumber,
                            'revocationDate' => $revocationDate,
                            'reasonCode' => $reasonCode,
                        ];
                    }
                }
                $crlInfo['revoked'] = $revokedCerts;
                
            } finally {
                // 清理临时文件
                @unlink($tempFile);
            }
            
            // 创建CRL对象
            $issuerDN = $crlInfo['issuer'] ?? '';
            $thisUpdate = isset($crlInfo['lastUpdate']) ? new DateTimeImmutable($crlInfo['lastUpdate']) : new DateTimeImmutable();
            $nextUpdate = isset($crlInfo['nextUpdate']) ? new DateTimeImmutable($crlInfo['nextUpdate']) : null;
            $crlNumber = $crlInfo['crlNumber'] ?? '0';
            $signatureAlgorithm = $crlInfo['signatureAlgorithm'] ?? null;
            
            $crl = new CertificateRevocationList(
                $issuerDN,
                $thisUpdate,
                $nextUpdate,
                $crlNumber,
                $signatureAlgorithm,
                null, // 签名值需要另外提取
                $derData
            );
            
            // 解析撤销条目
            $revokedCerts = $crlInfo['revoked'] ?? [];
            foreach ($revokedCerts as $cert) {
                $serialNumber = $cert['serialNumber'] ?? '';
                $revocationDate = isset($cert['revocationDate']) ? new DateTimeImmutable($cert['revocationDate']) : new DateTimeImmutable();
                $reasonCode = null;
                if (isset($cert['reasonCode'])) {
                    // 将文本形式的原因代码转换为数字
                    $reasonMap = [
                        'Unspecified' => 0,
                        'Key Compromise' => 1,
                        'CA Compromise' => 2,
                        'Affiliation Changed' => 3,
                        'Superseded' => 4,
                        'Cessation Of Operation' => 5,
                        'Certificate Hold' => 6,
                        'Remove From CRL' => 8,
                        'Privilege Withdrawn' => 9,
                        'AA Compromise' => 10,
                    ];
                    
                    foreach ($reasonMap as $text => $code) {
                        if (strpos($cert['reasonCode'], $text) !== false) {
                            $reasonCode = $code;
                            break;
                        }
                    }
                }
                
                $invalidityDate = null;
                
                $entry = new CRLEntry($serialNumber, $revocationDate, $reasonCode, $invalidityDate);
                $crl->addRevokedCertificate($entry);
            }
            
            return $crl;
        } catch (CRLException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw CRLException::parseError('解析DER数据失败: ' . $e->getMessage());
        }
    }
    
    /**
     * 从URL获取并解析CRL
     *
     * @param string $url CRL的URL
     * @return CertificateRevocationList 解析后的CRL
     * @throws CRLException 如果获取或解析失败
     */
    public function fetchFromURL(string $url): CertificateRevocationList
    {
        try {
            // 获取CRL数据
            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'timeout' => 30,
                    'header' => 'User-Agent: TLS-Certificate/1.0'
                ]
            ]);
            
            $crlData = @file_get_contents($url, false, $context);
            if ($crlData === false) {
                throw CRLException::notFound($url);
            }
            
            // 根据内容类型选择解析方法
            if (strpos($crlData, '-----BEGIN') !== false) {
                return $this->parsePEM($crlData);
            } else {
                return $this->parseDER($crlData);
            }
        } catch (CRLException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw CRLException::notFound($url . ': ' . $e->getMessage());
        }
    }
    
    /**
     * 从证书中提取CRL分发点
     *
     * @param mixed $certificate 要提取CRL分发点的证书
     * @return array<string> CRL分发点URL列表
     */
    public function extractCRLDistributionPoints($certificate): array
    {
        // 如果证书是X509Certificate类型，直接获取CRL分发点
        if ($certificate instanceof \Tourze\TLSCertificate\Certificate\X509Certificate) {
            return $certificate->getCRLDistributionPoints() ?? [];
        }
        
        // 其他情况返回空数组
        return [];
    }
} 