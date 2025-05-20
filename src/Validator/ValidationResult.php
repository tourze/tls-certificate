<?php

declare(strict_types=1);

namespace Tourze\TLSCertificate\Validator;

/**
 * 验证结果类 - 用于存储证书验证过程中的结果信息
 */
class ValidationResult
{
    /**
     * @var array<string> 成功信息
     */
    private array $successes = [];
    
    /**
     * @var array<string> 信息性消息
     */
    private array $infos = [];
    
    /**
     * @var array<string> 警告信息
     */
    private array $warnings = [];
    
    /**
     * @var array<string> 错误信息
     */
    private array $errors = [];
    
    /**
     * 添加成功信息
     *
     * @param string $message 成功信息
     * @return $this
     */
    public function addSuccess(string $message): self
    {
        $this->successes[] = $message;
        return $this;
    }
    
    /**
     * 添加信息性消息
     *
     * @param string $message 信息性消息
     * @return $this
     */
    public function addInfo(string $message): self
    {
        $this->infos[] = $message;
        return $this;
    }
    
    /**
     * 添加警告信息
     *
     * @param string $message 警告信息
     * @return $this
     */
    public function addWarning(string $message): self
    {
        $this->warnings[] = $message;
        return $this;
    }
    
    /**
     * 添加错误信息
     *
     * @param string $message 错误信息
     * @return $this
     */
    public function addError(string $message): self
    {
        $this->errors[] = $message;
        return $this;
    }
    
    /**
     * 检查验证是否有效（无错误）
     *
     * @return bool 如果验证有效（无错误）则返回true
     */
    public function isValid(): bool
    {
        return empty($this->errors);
    }
    
    /**
     * 获取所有成功信息
     *
     * @return array<string>
     */
    public function getSuccesses(): array
    {
        return $this->successes;
    }
    
    /**
     * 获取所有信息性消息
     *
     * @return array<string>
     */
    public function getInfos(): array
    {
        return $this->infos;
    }
    
    /**
     * 获取所有警告信息
     *
     * @return array<string>
     */
    public function getWarnings(): array
    {
        return $this->warnings;
    }
    
    /**
     * 获取所有错误信息
     *
     * @return array<string>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }
    
    /**
     * 合并另一个验证结果
     *
     * @param ValidationResult $other 要合并的验证结果
     * @return $this
     */
    public function merge(ValidationResult $other): self
    {
        $this->successes = array_merge($this->successes, $other->getSuccesses());
        $this->infos = array_merge($this->infos, $other->getInfos());
        $this->warnings = array_merge($this->warnings, $other->getWarnings());
        $this->errors = array_merge($this->errors, $other->getErrors());
        
        return $this;
    }
    
    /**
     * 获取所有消息
     *
     * @return array<string, array<string>>
     */
    public function getAllMessages(): array
    {
        return [
            'successes' => $this->successes,
            'infos' => $this->infos,
            'warnings' => $this->warnings,
            'errors' => $this->errors,
        ];
    }
    
    /**
     * 清除所有消息
     *
     * @return $this
     */
    public function clear(): self
    {
        $this->successes = [];
        $this->infos = [];
        $this->warnings = [];
        $this->errors = [];
        
        return $this;
    }
} 