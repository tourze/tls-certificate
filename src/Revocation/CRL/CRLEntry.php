<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Revocation\CRL;

use DateTimeImmutable;

/**
 * CRL撤销条目 - 表示CRL中的一个撤销证书
 */
class CRLEntry
{
    /**
     * 撤销原因常量
     */
    public const REASON_UNSPECIFIED = 0;
    public const REASON_KEY_COMPROMISE = 1;
    public const REASON_CA_COMPROMISE = 2;
    public const REASON_AFFILIATION_CHANGED = 3;
    public const REASON_SUPERSEDED = 4;
    public const REASON_CESSATION_OF_OPERATION = 5;
    public const REASON_CERTIFICATE_HOLD = 6;
    public const REASON_REMOVE_FROM_CRL = 8;
    public const REASON_PRIVILEGE_WITHDRAWN = 9;
    public const REASON_AA_COMPROMISE = 10;
    
    /**
     * @var string 证书序列号
     */
    private string $serialNumber;
    
    /**
     * @var DateTimeImmutable 撤销时间
     */
    private DateTimeImmutable $revocationDate;
    
    /**
     * @var int|null 撤销原因
     */
    private ?int $reasonCode;
    
    /**
     * @var DateTimeImmutable|null 失效日期
     */
    private ?DateTimeImmutable $invalidityDate;
    
    /**
     * 构造函数
     *
     * @param string $serialNumber 证书序列号
     * @param DateTimeImmutable $revocationDate 撤销时间
     * @param int|null $reasonCode 撤销原因代码
     * @param DateTimeImmutable|null $invalidityDate 失效日期
     */
    public function __construct(
        string $serialNumber,
        DateTimeImmutable $revocationDate,
        ?int $reasonCode = null,
        ?DateTimeImmutable $invalidityDate = null
    ) {
        $this->serialNumber = $serialNumber;
        $this->revocationDate = $revocationDate;
        $this->reasonCode = $reasonCode;
        $this->invalidityDate = $invalidityDate;
    }
    
    /**
     * 获取证书序列号
     *
     * @return string
     */
    public function getSerialNumber(): string
    {
        return $this->serialNumber;
    }
    
    /**
     * 获取撤销时间
     *
     * @return DateTimeImmutable
     */
    public function getRevocationDate(): DateTimeImmutable
    {
        return $this->revocationDate;
    }
    
    /**
     * 获取撤销原因代码
     *
     * @return int|null
     */
    public function getReasonCode(): ?int
    {
        return $this->reasonCode;
    }
    
    /**
     * 获取失效日期
     *
     * @return DateTimeImmutable|null
     */
    public function getInvalidityDate(): ?DateTimeImmutable
    {
        return $this->invalidityDate;
    }
    
    /**
     * 获取撤销原因文本
     *
     * @return string 撤销原因的文本描述
     */
    public function getReasonText(): string
    {
        $reasonMap = [
            self::REASON_UNSPECIFIED => '未指定',
            self::REASON_KEY_COMPROMISE => '密钥泄露',
            self::REASON_CA_COMPROMISE => 'CA证书泄露',
            self::REASON_AFFILIATION_CHANGED => '附属关系变更',
            self::REASON_SUPERSEDED => '被替代',
            self::REASON_CESSATION_OF_OPERATION => '停止运营',
            self::REASON_CERTIFICATE_HOLD => '证书暂停',
            self::REASON_REMOVE_FROM_CRL => '从CRL移除',
            self::REASON_PRIVILEGE_WITHDRAWN => '权限被撤销',
            self::REASON_AA_COMPROMISE => 'AA泄露'
        ];
        
        if ($this->reasonCode === null) {
            return '未指定';
        }
        
        return $reasonMap[$this->reasonCode] ?? '未知(' . $this->reasonCode . ')';
    }
} 