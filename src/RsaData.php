<?php
/**
 * Class RasData
 */

class RsaData
{
    private $privateKey = '';
    private $publicKey = '';

    public function __construct($privateKey, $publicKey = false)
    {
        if ($privateKey && openssl_pkey_get_private($privateKey)) {
            $this->privateKey = $privateKey;
        } else {
            throw new Exception('秘钥信息不正确', 500);
        }

        if ($publicKey) {
            if (openssl_pkey_get_public($publicKey)) {
                $this->publicKey = $publicKey;
            } else {
                throw new Exception('公钥信息不正确', 500);
            }
        }
    }

    public function getPublicKey ()
    {
        return $this->publicKey;
    }


    /*
     * 服务端加密数据（使用私钥加密， 公钥可以解密）
     */
    public function ServerEncodeData($data)
    {
        $encryptData = '';
        if (!is_array($data)) throw new Exception('加密数据格式应为字符串');
        openssl_private_encrypt(json_encode($data, true), $encryptData, $this->privateKey);

        return base64_encode($encryptData);//加密后的内容通常含有特殊字符，需要编码转换下
    }

    /*
     * 客户端解密数据（使用公钥解密， 可解私钥加密数据）
     */
    public function ClientDecodeData($data)
    {
        $decryptData = '';
        if (!is_string($data)) throw new Exception('解密格式应为字符串格式');
        if (!$this->publicKey) throw new Exception('客户端解密需要提供公钥');

        openssl_public_decrypt(base64_decode($data), $decryptData, $this->publicKey);

        return json_decode($decryptData, true);
    }

    /*
     * 客户端加解数据（使用公钥加密， 私钥可解密）
     */
    public function ClientEncodeData($data)
    {
        $encryptData = '';
        if (!is_array($data)) throw new Exception('加密数据格式应为字符串');
        if (!$this->publicKey) throw new Exception('客户端加密需要提供公钥');

        openssl_public_encrypt(json_encode($data, true), $encryptData, $this->publicKey);

        return base64_encode($encryptData);//加密后的内容通常含有特殊字符，需要编码转换下
    }

    /*
     * 服务端解密数据（使用私钥解密， 公钥加密数据私钥可解）
     */
    public function ServerDecodeData($data)
    {
        $decryptData = '';
        if (!is_string($data)) throw new Exception('解密格式应为字符串格式');

        openssl_private_decrypt(base64_decode($data), $decryptData, $this->privateKey);

        return json_decode($decryptData, true);
    }
}