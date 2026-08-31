package com.slaunchx.plutus.sdk.crypto;

import com.slaunchx.plutus.sdk.exception.PlutusCryptoException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * 混合加密信封的封装与拆封:RSA-OAEP-SHA256 包装一次性 AES-256 密钥,AES-256-GCM 加密载荷。
 *
 * <p>固定参数:AES/GCM/NoPadding,密钥 256 位,IV 12 字节前置,认证标签 16 字节后置,
 * RSA/ECB/OAEPWithSHA-256AndMGF1Padding,<b>MGF1 摘要显式设为 SHA-256</b>(JCA 默认为 SHA-1,
 * 使用默认值会导致解密失败且无提示),OAEP label 为空,Base64 为带填充的标准变体。
 *
 * <p>拆封时先用本地上下文重建 AAD,与信封回显的 {@code aad} 做常量时间比较,
 * 再用<b>重建的</b> AAD 做 GCM 解密。直接使用回显值等于放弃 AAD 的绑定作用。
 */
public final class EnvelopeCodec {

    /** GCM IV 长度(字节)。 */
    public static final int IV_LENGTH = 12;

    /** GCM 认证标签长度(位)。 */
    public static final int TAG_LENGTH_BITS = 128;

    /** AES 密钥长度(字节)。 */
    public static final int AES_KEY_LENGTH = 32;

    /** 明文长度上限,1 MiB。 */
    public static final int MAX_PLAINTEXT_BYTES = 1024 * 1024;

    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecureRandom random;

    /**
     * 使用默认 {@link SecureRandom} 构造。
     */
    public EnvelopeCodec() {
        this(new SecureRandom());
    }

    /**
     * @param random 随机源,用于生成一次性 AES 密钥与 IV
     */
    public EnvelopeCodec(SecureRandom random) {
        this.random = random == null ? new SecureRandom() : random;
    }

    /**
     * 封装 API 链信封(含 {@code encryptedPayload} 兼容字段)。
     *
     * @param plaintext           明文字节
     * @param recipientPublicKey  接收方公钥
     * @param recipientFingerprint 接收方公钥指纹,写入 {@code keyFingerprint}
     * @param aad                 附加认证数据
     * @return 信封
     * @throws PlutusCryptoException 明文超限或加密失败时抛出
     */
    public Envelope seal(byte[] plaintext, RSAPublicKey recipientPublicKey,
                         String recipientFingerprint, EncryptionAad aad) {
        if (plaintext == null) {
            throw new PlutusCryptoException("明文为空");
        }
        if (plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new PlutusCryptoException("明文长度超过 1 MiB 上限");
        }
        byte[] aesKey = new byte[AES_KEY_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(aesKey);
        random.nextBytes(iv);
        byte[] aadBytes = aad.bytes();
        try {
            Cipher aes = Cipher.getInstance(AES_TRANSFORMATION);
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            aes.updateAAD(aadBytes);
            byte[] sealed = aes.doFinal(plaintext);

            byte[] blob = new byte[iv.length + sealed.length];
            System.arraycopy(iv, 0, blob, 0, iv.length);
            System.arraycopy(sealed, 0, blob, iv.length, sealed.length);

            Cipher rsa = Cipher.getInstance(RSA_TRANSFORMATION);
            rsa.init(Cipher.ENCRYPT_MODE, recipientPublicKey, oaepParameters());
            byte[] wrappedKey = rsa.doFinal(aesKey);

            return Envelope.apiEnvelope(recipientFingerprint,
                    Base64.getEncoder().encodeToString(wrappedKey),
                    Base64.getEncoder().encodeToString(blob),
                    aad.base64());
        } catch (PlutusCryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new PlutusCryptoException("信封封装失败", e);
        } finally {
            Arrays.fill(aesKey, (byte) 0);
        }
    }

    /**
     * 封装明文字符串。
     *
     * @param plaintext           明文,按 UTF-8 编码
     * @param recipientPublicKey  接收方公钥
     * @param recipientFingerprint 接收方公钥指纹
     * @param aad                 附加认证数据
     * @return 信封
     */
    public Envelope seal(String plaintext, RSAPublicKey recipientPublicKey,
                         String recipientFingerprint, EncryptionAad aad) {
        return seal(plaintext.getBytes(StandardCharsets.UTF_8), recipientPublicKey, recipientFingerprint, aad);
    }

    /**
     * 拆封信封。
     *
     * <p>流程:重建 AAD 的 Base64 → 与信封回显值常量时间比较 → RSA-OAEP 解出 AES 密钥
     * → 校验密钥长度 32 字节 → 切分 {@code IV || 密文 || 标签} → GCM 解密 → 校验明文长度上限。
     *
     * @param envelope    信封(形状应先经 {@link Envelope#requireApiShape()} 或
     *                    {@link Envelope#requireWebhookShape()} 校验)
     * @param privateKey  接收方私钥
     * @param expectedAad 本地重建的 AAD
     * @return 明文字节
     * @throws PlutusCryptoException AAD 不匹配、解包失败、GCM 认证失败或明文超限时抛出
     */
    public byte[] open(Envelope envelope, RSAPrivateKey privateKey, EncryptionAad expectedAad) {
        if (envelope == null) {
            throw new PlutusCryptoException("信封为空");
        }
        byte[] expectedAadBytes = expectedAad.bytes();
        byte[] echoedAadBytes;
        try {
            echoedAadBytes = Base64.getDecoder().decode(envelope.aad());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new PlutusCryptoException("信封 aad 不是合法 Base64");
        }
        if (!MessageDigest.isEqual(expectedAadBytes, echoedAadBytes)) {
            throw new PlutusCryptoException("信封 aad 与本地重建的 AAD 不一致, 拒绝解密");
        }

        byte[] aesKey = null;
        try {
            Cipher rsa = Cipher.getInstance(RSA_TRANSFORMATION);
            rsa.init(Cipher.DECRYPT_MODE, privateKey, oaepParameters());
            aesKey = rsa.doFinal(Base64.getDecoder().decode(envelope.encryptedKey()));
            if (aesKey.length != AES_KEY_LENGTH) {
                throw new PlutusCryptoException("解出的 AES 密钥长度必须为 32 字节");
            }
            byte[] blob = Base64.getDecoder().decode(envelope.ciphertext());
            if (blob.length < IV_LENGTH + TAG_LENGTH_BITS / 8) {
                throw new PlutusCryptoException("密文块长度不足以容纳 IV 与认证标签");
            }
            Cipher aes = Cipher.getInstance(AES_TRANSFORMATION);
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new GCMParameterSpec(TAG_LENGTH_BITS, blob, 0, IV_LENGTH));
            aes.updateAAD(expectedAadBytes);
            byte[] plaintext = aes.doFinal(blob, IV_LENGTH, blob.length - IV_LENGTH);
            if (plaintext.length > MAX_PLAINTEXT_BYTES) {
                throw new PlutusCryptoException("解密后明文超过 1 MiB 上限");
            }
            return plaintext;
        } catch (PlutusCryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new PlutusCryptoException("信封拆封失败: " + e.getClass().getSimpleName());
        } finally {
            if (aesKey != null) {
                Arrays.fill(aesKey, (byte) 0);
            }
        }
    }

    /**
     * 拆封并按 UTF-8 解码。
     *
     * @param envelope    信封
     * @param privateKey  接收方私钥
     * @param expectedAad 本地重建的 AAD
     * @return 明文字符串
     */
    public String openToString(Envelope envelope, RSAPrivateKey privateKey, EncryptionAad expectedAad) {
        return new String(open(envelope, privateKey, expectedAad), StandardCharsets.UTF_8);
    }

    private static OAEPParameterSpec oaepParameters() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }
}
