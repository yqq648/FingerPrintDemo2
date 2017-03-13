package com.example.yq.fingerprintdemo2;

import android.Manifest;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.widget.Toast;

import java.security.KeyStore;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {
    private FingerprintManager.CryptoObject crytoObject;

    /**
     * 指纹识别的使用
     * 0.手机系统在6.0以上系统哦
     * 1.判断手机是否启用了密码解锁+指纹解锁
     *
     * a. 6.0以上系统才能使用
     * b. 添加指纹权限USE_FINGERPRINT
     * c. 第三个参数 callback
     * d. 动态权限警告
     * =============
     * 0.不用拿到指纹的内容，非常的简单.
     * 1.拿到指纹成功的内容
     * 2.系统是否支持指纹识别
     * onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
     *
     * @param savedInstanceState
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if (Build.VERSION.SDK_INT<Build.VERSION_CODES.M){//判断当前版本是否大于
            Toast.makeText(this, "当前版本不支持指纹识别", Toast.LENGTH_SHORT).show();
            return;
        }
        FingerprintManager fingerprintManager =
                (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
        if (!fingerprintManager.hasEnrolledFingerprints()){//指纹解锁
            Toast.makeText(this, "你没有录制有效的指纹解锁", Toast.LENGTH_SHORT).show();
            return;
        }


        CancellationSignal cancel = new CancellationSignal();
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            // TODO: Consider calling
            //    ActivityCompat#requestPermissions
            // here to request the missing permissions, and then overriding
            //   public void onRequestPermissionsResult(int requestCode, String[] permissions,
            //                                          int[] grantResults)
            // to handle the case where the user grants the permission. See the documentation
            // for ActivityCompat#requestPermissions for more details.
            return;
        }//设置
        FingerprintManager.CryptoObject crypto = null;
        try {
            crypto = getCrytoObject();//传递加密对象
        } catch (Exception e) {
            throw new RuntimeException("初始化 失败", e);
        }
        fingerprintManager.authenticate(crypto, cancel, 0, new FingerprintManager.AuthenticationCallback() {
            @Override//result指纹的内容
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                FingerprintManager.CryptoObject c = result.getCryptoObject();
                //指纹的内容.
                try {//拿到CryptoObject-》Cipher-》doFinal-》byte->Base64.encodeToString
                    Toast.makeText(MainActivity.this, "成功" +Base64.encodeToString(c.getCipher().doFinal(), Base64.URL_SAFE),
                            Toast.LENGTH_SHORT).show();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(MainActivity.this, "失败", Toast.LENGTH_SHORT).show();
            }

            @Override//失败5次以上，指纹识别被禁用1分钟
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(MainActivity.this, "指纹识别被禁用1分钟 ", Toast.LENGTH_SHORT).show();
            }

            @Override// "Sensor dirty, please clean it." 你按下的不是手指，或者你手指太脏了，手指上有很多水.....
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
                Toast.makeText(MainActivity.this, "请擦干你的手指，再来一次", Toast.LENGTH_SHORT).show();
            }
        }, null);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public FingerprintManager.CryptoObject getCrytoObject() throws Exception {
        //1.KeyStore 加密信息存储的地方Store
        KeyStore mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        //2.KeyGenerator加密信息生成的对象Generator
        KeyGenerator mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        //3.KeyGeneratorBuilder 要生成的某个对象构造器
        final String defaultKeyName = "default_key";
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(defaultKeyName,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

        mKeyGenerator.init(builder.build());
        mKeyGenerator.generateKey();
        //TODO 4 Cipher
        Cipher defaultCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        mKeyStore.load(null);
        SecretKey key = (SecretKey) mKeyStore.getKey(defaultKeyName, null);
        defaultCipher.init(Cipher.ENCRYPT_MODE, key);
        return new FingerprintManager.CryptoObject(defaultCipher);
    }
}
