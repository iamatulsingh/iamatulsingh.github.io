---
title: Uncrackable - Level 1 | OWASP
date: 2024-05-21 00:00:00 +200
categories: [owasp, ctf, mobile, pentesting, uncrackable]
tags: [owasp, ctf, mobile, pentesting, uncrackable]
---

# OWASP Uncrackable | Level 1

Let's dive into analyzing the `OWASP Uncrackable Level 1` app!


This can be solved in two ways,
1. Using frida (not required here!)
2. Using normal code analysis and write your own code from that.

I'll show you both ways. So let's buckle up for both of the way to solve this challenge.

>Using Frida
{: .prompt-info }

## Root Detection

Upon opening the app, it closes due to root detection, as shown below:
![Permission](/assets/images/uncrackable_level1/root_detection_prompt_uncrackable_level1.png){: width="350" }

To understand why, we can decompile the APK using `Jadx`. In the `AndroidManifest.xml`, the Launcher activity is defined as` owasp.mstg.uncrackable1`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="1"
    android:versionName="1.0"
    package="owasp.mstg.uncrackable1">
    <uses-sdk
        android:minSdkVersion="19"
        android:targetSdkVersion="28"/>
    <application
        android:theme="@style/AppTheme"
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        android:allowBackup="true">
        <activity
            android:label="@string/app_name"
            android:name="sg.vantagepoint.uncrackable1.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

In `MainActivity`, we find the code responsible for detecting root and closing the app using `System.exit(0);`.

![Root Detection](/assets/images/uncrackable_level1/root_detection_uncrackable_level1.png)

```java
private void a(String str) {
    AlertDialog create = new AlertDialog.Builder(this).create();
    create.setTitle(str);
    create.setMessage("This is unacceptable. The app is now going to exit.");
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.1
        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);
        }
    });
    create.setCancelable(false);
    create.show();
}


@Override // android.app.Activity
protected void onCreate(Bundle bundle) {
    if (c.a() || c.b() || c.c()) {
        a("Root detected!");
    }
    if (b.a(getApplicationContext())) {
        a("App is debuggable!");
    }
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
}
```

## Bypassing Root Detection
Let's write a `frida` script to hook and bypass this check.

```js
Java.perform(function() {
    var hook = Java.use("java.lang.System");
    hook.exit.implementation = function() {
        console.log("Root Check Bypassed!!! 😎");
    };
});
```

## App Functionality

Once bypassed, the app presents a text field and a verify button. Clicking `verify` shows a message: `That's not it. Try again.`.

By searching for this string in the code, we find the verification logic:

![Verify Prompt](/assets/images/uncrackable_level1/try_again_prompt_uncrackable_level1.png)

Let's take this as a reference to move ahead and find this string in the code. After searching this out, you can see a code like below which seems like a comparison between input value and some hard coded value.

![Verify Code](/assets/images/uncrackable_level1/verify_uncrackable_level1.png)

```java
public void verify(View view) {
    String str;
    String obj = ((EditText) findViewById(R.id.edit_text)).getText().toString();
    AlertDialog create = new AlertDialog.Builder(this).create();
    if (a.a(obj)) {
        create.setTitle("Success!");
        str = "This is the correct secret.";
    } else {
        create.setTitle("Nope...");
        str = "That's not it. Try again.";
    }
    create.setMessage(str);
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.2
        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            dialogInterface.dismiss();
        }
    });
    create.show();
}
```

## Analyzing the Verification Logic

We need to inspect the `a` method to understand the comparison.

![Comparison Code](/assets/images/uncrackable_level1/compare_uncrackable_level1.png)

```java
public class a {
    public static boolean a(String str) {
        byte[] bArr;
        byte[] bArr2 = new byte[0];
        try {
            bArr = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
        } catch (Exception e) {
            Log.d("CodeCheck", "AES error:" + e.getMessage());
            bArr = bArr2;
        }
        return str.equals(new String(bArr));
    }

    public static byte[] b(String str) {
        int length = str.length();
        byte[] bArr = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return bArr;
    }
}
```

The `bArr` value is what our input is being compared to. The `sg.vantagepoint.a.a.a` method is an AES decryption method.

![AES Cipher](/assets/images/uncrackable_level1/aes_cipher_uncrackable_level1.png)

```java
public class a {
    public static byte[] a(byte[] bArr, byte[] bArr2) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES/ECB/PKCS7Padding");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(2, secretKeySpec);
        return cipher.doFinal(bArr2);
    }
}
```

## Hooking the AES Cipher function 

We can hook this function to get the string value.

```js
var a = Java.use('sg.vantagepoint.a.a');
a.a.implementation = function (p0, p1) {
    console.log('p0 (byte array): ' + bytesToString(p0));
    console.log('p1 (byte array): ' + bytesToString(p1));
    
    var result = this.a(p0, p1);
    console.log("Result ->", bytesToString(result))
    return result;
};

function bytesToString(bytes) {
    var result = '';
    for (var i = 0; i < bytes.length; ++i) {
        result += String.fromCharCode(bytes[i]);
    }
    return result;
}
```

## Running the Script

Execute the script to see the byte array as string.

```cmd
(base) C:\Users\booyaa\uncrackable\level> frida -U -l ./hook_level1.js -f owasp.mstg.uncrackable1
     ____
    / _  |   Frida 16.2.3 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to LE2001 (id=4a298ca9)
Spawned `owasp.mstg.uncrackable1`. Resuming main thread!
[LE2101::owasp.mstg.uncrackable1 ]-> Hooked exit()
Root Check Bypassed!!! 😎
p0 (byte array): ﾍvﾄￋￃ|amﾀl￵sￌ
p1 (byte array): ￥Bbￋ[ﾚￃﾠﾵ￦ﾤﾽvﾚI￨￰t￸.￿ﾕﾫ|v￧
Result -> I want to believe
Process terminated
[LE2101::owasp.mstg.uncrackable1 ]->

Thank you for using Frida!
(base) C:\Users\booyaa\uncrackable\level>
```

![Final Result](/assets/images/uncrackable_level1/result_uncrackable_level1.gif)

And there we have it, the final string: `I want to believe`.

>Using just python and no rooted device or frida
{: .prompt-info }


```python
# level1.py

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def a(key, cipher_text):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(cipher_text), AES.block_size)

def b(hex_string):
    return bytes.fromhex(hex_string)

try:
    key = b("8d127684cbc37c17616d806cf50473cc")
    cipher_text = base64.b64decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=")
    returned_bytes = a(key, cipher_text)
    print("Solved: ", returned_bytes.decode())
except Exception as e:
    print("AES error: ", str(e))
```

```bash
pip install pycryptodome
```

```bash
$ python level1.py
Solved:  I want to believe
```

Thanks for following along! Cheers 🍺
