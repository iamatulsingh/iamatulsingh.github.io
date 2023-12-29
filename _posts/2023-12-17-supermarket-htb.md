---
title: Supermarket - Hack The Box (htb) | 40 points
date: 2023-12-17 12:00:00 +100
categories: [hackthebox, ctf, supermarket]
tags: [ctf, hackthebox, supermarket]
---

Challenge: <a href="https://app.hackthebox.com/challenges/supermarket">Supermaket (HTB | Hack the box): 40 points</a>

It took me just 3-4 minutes for completeing this challange (inlcuding decompile, patch the code and recompile).

There are multiple ways to solve this challenge, like:

- [ ] Read the encrypted strings from `jni` and write a script in any chosen language to decrypt it.
- [ ] Hook the function and read the value from it which will require a rooted android phone/emulator.
- [x] Use some own custom tool and save some precious time `(Which I did by the way)`.

If you see the code after decompiling, you can see that it's reading strings from a `jni` library name `supermarket` which is present in `lib` folder.

```java
static {
        System.loadLibrary("supermarket");
    }
```

I already have some of my self written tool specially for reverse engineering so I didn't even bother to check that `supermarket.so` and wrote a script to get the string and decrypt it. I simply used my tool to inject in the app and got the decrypted string. Please check the original and patched code I mentioned below. I'm not pasting my code to receive that string on Telegram. Below is the java similar code snippet from the decompiled apk.

I needed to focus here just to read the `new String(cipher.doFinal(Base64.decode(stringFromJNI, 0)), "utf-8")` instead of going to the `jni` file and the decrypt the encrypted string and writing code for doing tha. This is because I have a smali code using which I can send this string to that and I'll receive from that.


```java
@Override
public void onTextChanged(CharSequence charSequence, int i2, int i3, int i4) {
    try {
        ...
        if (!obj.equals(new String(cipher.doFinal(Base64.decode(stringFromJNI, 0)), "utf-8"))) {
            MainActivity.this.f2081w.clear();
            MainActivity.this.f2076r = 5.0d;
            while (true) {
                String[] strArr = this.f2085c;
                if (i5 >= strArr.length) {
                    break;
                }
                MainActivity.this.f2081w.add(strArr[i5]);
                i5++;
            }
        }
        ...
    } catch (Exception e2) {
        e2.printStackTrace();
    }
    MainActivity.this.s();
}
```

Code of interest from the decompiled apk (smali)

```text
.method public onTextChanged(Ljava/lang/CharSequence;III)V
    ...

    .line 2
    invoke-virtual {p2}, Lcom/example/supermarket/MainActivity;->stringFromJNI3()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    move-result-object p2

    const/4 v0, 0x2

    invoke-virtual {p2, v0, p4}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    const/4 p4, 0x0

    invoke-static {p3, p4}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p3

    invoke-virtual {p2, p3}, Ljavax/crypto/Cipher;->doFinal([B)[B

    move-result-object p2

    new-instance p3, Ljava/lang/String;

    const-string v0, "utf-8"

    invoke-direct {p3, p2, v0}, Ljava/lang/String;-><init>([BLjava/lang/String;)V

    ...

    return-void
.end method
```

<hr>

Injecting code:

```text
;these are the 6 lines of code in smali I injected into the original APK
;to call my smali module with telegram code.

const-string v3, "Coupon-Code: "

invoke-static {p3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

move-result-object v4

new-instance v5, Lcom/example/supermarket/SendTelegram;

invoke-direct {v5}, Lcom/example/supermarket/SendTelegram;-><init>()V

invoke-virtual {v5, v3, p3}, Lcom/example/supermarket/SendTelegram;->sendMessage(Ljava/lang/String;Ljava/lang/String;)V
```

Last but not least, don't forget to add internet permisison to the manifest.

Now I just simply type anything in the coupon box and I got the result message in my telegram. 

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="31" android:compileSdkVersionCodename="12" package="com.example.supermarket" platformBuildVersionCode="31" platformBuildVersionName="12">
    <!-- Add this -->
    <uses-permission android:name="android.permission.INTERNET"/>
    
    <application android:allowBackup="true" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:roundIcon="@mipmap/ic_launcher_round" android:supportsRtl="true" android:theme="@style/Theme.Supermarket">
        <activity android:exported="true" android:name="com.example.supermarket.MainActivity" android:windowSoftInputMode="adjustPan">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider android:authorities="com.example.supermarket.androidx-startup" android:exported="false" android:name="androidx.startup.InitializationProvider">
            <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/>
        </provider>
    </application>
</manifest>
```


| ![space-1.jpg](/assets/screenshots/sidebar.png){: width="350" } | ![space-1.jpg](/assets/screenshots/result.jpg){: width="320" } | 
|:--:|:--:| 
| *Folder with injected smali file* | *Result* |


<hr>

>FLAG: `HTB{n0_xxxx_xxxxxxx_xxxxx@uc3!}`
{: .prompt-info }