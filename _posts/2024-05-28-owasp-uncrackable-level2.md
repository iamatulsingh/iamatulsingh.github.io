---
title: Uncrackable - Level 2 | OWASP
date: 2024-05-28 00:00:00 +200
categories: [owasp, ctf, mobile, pentesting, uncrackable]
tags: [owasp, ctf, mobile, pentesting, uncrackable]
---

# OWASP Uncrackable | Level 2

Let's dive into analyzing the `OWASP Uncrackable Level 2` app!


## Root Detection

To understand why, we can decompile the APK using jadx. In the `AndroidManifest.xml`, the Launcher activity is defined as `owasp.mstg.uncrackable2`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="1"
    android:versionName="1.0"
    android:compileSdkVersion="28"
    android:compileSdkVersionCodename="9"
    package="owasp.mstg.uncrackable2"
    platformBuildVersionCode="1"
    platformBuildVersionName="1">
    <uses-sdk
        android:minSdkVersion="19"
        android:targetSdkVersion="28"/>
    <application
        android:theme="@style/AppTheme"
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        android:allowBackup="true"
        android:supportsRtl="true">
        <activity android:name="sg.vantagepoint.uncrackable2.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

In `MainActivity`, we find the code responsible for detecting root and closing the app using `System.exit(0);`.

![Root Detection](/assets/images/root_detection_uncrackable_level1.png)

```java
public void a(String str) {
    AlertDialog create = new AlertDialog.Builder(this).create();
    create.setTitle(str);
    create.setMessage("This is unacceptable. The app is now going to exit.");
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable2.MainActivity.1
        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            System.exit(0);
        }
    });
    create.setCancelable(false);
    create.show();
}


@Override // android.support.v7.app.c, android.support.v4.app.h, android.support.v4.app.z, android.app.Activity
public void onCreate(Bundle bundle) {
    init();
    if (b.a() || b.b() || b.c()) {
        a("Root detected!");
    }
    if (a.a(getApplicationContext())) {
        a("App is debuggable!");
    }
    new AsyncTask<Void, String, String>() { // from class: sg.vantagepoint.uncrackable2.MainActivity.2
        /* JADX DEBUG: Method merged with bridge method: doInBackground([Ljava/lang/Object;)Ljava/lang/Object; */
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public String doInBackground(Void... voidArr) {
            while (!Debug.isDebuggerConnected()) {
                SystemClock.sleep(100L);
            }
            return null;
        }

        /* JADX DEBUG: Method merged with bridge method: onPostExecute(Ljava/lang/Object;)V */
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public void onPostExecute(String str) {
            MainActivity.this.a("Debugger detected!");
        }
    }.execute(null, null, null);
    this.m = new CodeCheck();
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

By searching for this string in the code, we find the verification logic (Same in both Uncrackable 1 and 2):

![Verify Prompt](/assets/images/try_again_prompt_uncrackable_level1.png)

Let's take this as a reference to move ahead and find this string in the code. After searching this out, you can see a code like below which seems like a comparison between input value and some hard coded value.

![Verify Code](/assets/images/verify_uncrackable_level1.png)

```java
public void verify(View view) {
    String str;
    String obj = ((EditText) findViewById(R.id.edit_text)).getText().toString();
    AlertDialog create = new AlertDialog.Builder(this).create();
    if (this.m.a(obj)) {
        create.setTitle("Success!");
        str = "This is the correct secret.";
    } else {
        create.setTitle("Nope...");
        str = "That's not it. Try again.";
    }
    create.setMessage(str);
    create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable2.MainActivity.3
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

![Nativ Lib](/assets/images/native_lib_uncrackable_level2.png)
![Comparison Code](/assets/images/compare_uncrackable_level2.png)

```java
public class CodeCheck {
    private native boolean bar(byte[] bArr);

    public boolean a(String str) {
        return bar(str.getBytes());
    }
}
```

Function `bar(str.getBytes())` is returning `true or false` and this seems to be a native fucntion as mentioned `private native boolean bar(byte[] bArr);` and to analyze `bar` function, let's open `Ghidra`.

![Ghidra Analysis](/assets/images/code_in_ghidra_uncrackable_level2.png)

```c
void Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
               (long *param_1,undefined8 param_2,undefined8 param_3)
{
  int iVar2;
  undefined8 uVar3;
  char *__s1;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  long local_38;
  long lVar1;
  
  lVar1 = tpidr_el0;
  local_38 = *(long *)(lVar1 + 0x28);
  uVar3 = 0;
  if (DAT_0011300c == '\x01') {
    uStack_48 = 0x74206c6c6120726f;
    local_50 = 0x6620736b6e616854;
    local_40 = 0x68736966206568;
    __s1 = (char *)(**(code **)(*param_1 + 0x5c0))(param_1,param_3,0);
    iVar2 = (**(code **)(*param_1 + 0x558))(param_1,param_3);
    if ((iVar2 == 0x17) && (iVar2 = strncmp(__s1,(char *)&local_50,0x17), iVar2 == 0)) {
      uVar3 = 1;
    }
    else {
      uVar3 = 0;
    }
  }
  if (*(long *)(lVar1 + 0x28) == local_38) {
    return;
  }
  
  /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar3);
}
```

The above code, which you can see in the `Ghidra`, explains alot. Point of focus is `strncmp(__s1,(char *)&local_50,0x17)` where `local_50` is getting used for character comparison and when you try that value from `local_50` which is `0x6620736b6e616854` in hexadecimal and convert that to string,

```python
>>> 0x6620736b6e616854.to_bytes(8)
b'f sknahT'
>>>
```

![String Check](/assets/images/half_result_ghidra_uncrackable_level2.png)

you'll get `b'f sknahT'` which seems like a string in reverse order i.e. `Thanks f`. That means, this is in little endian format and we can try all those hex to check what it generates. Last but not least, it also checking if the size of the string is 23 characters long using `0x17`.  

Now, there are two ways to solve this challenge. 
1. Using `frida`
2. Normal `python` code

Let's check both ways.

>Using Frida
{: .prompt-info }

```js
function hookNativeBar(){
    // use "get the secret for me!!" as an input because strncmp is required to have a string of length 23.
    console.log()
    setTimeout(function(){
        Interceptor.attach(Module.findExportByName('libfoo.so', 'strncmp'),{
            onEnter: function(args){
                if( Memory.readUtf8String(args[1]).length == 23 && Memory.readUtf8String(args[0]).includes("get the secret for me!!")){
                    console.log("[😉] Result ->", Memory.readUtf8String(args[1]))
                }
            },
            onLeave: function(retval){
            }
        });
    },2000);
}

Java.perform(function() {
    var hook = Java.use("java.lang.System");
    hook.exit.implementation = function() {
        console.log("[😎] Root Check Bypassed!!!");
    };
    hookNativeBar();
});
```


```bash
$ frida -U -f owasp.mstg.uncrackable2 -l .\hook_level2.js
     ____
    / _  |   Frida 16.2.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to LE2101 (id=4a298ca9)
Spawned `owasp.mstg.uncrackable2`. Resuming main thread!
[LE2101::owasp.mstg.uncrackable2 ]->
[😎] Root Check Bypassed!!!
[😉] Result -> Thanks for all the fish
Process terminated
[LE2101::owasp.mstg.uncrackable2 ]->

Thank you for using Frida!
```

![Final Result Frida](/assets/images/result_frida_uncrackable_level2.png)

>Using Python script
{: .prompt-info }

```python
# level2.py

# Hexadecimal values
hex_values = [
    0x6620736b6e616854,
    0x74206c6c6120726f,
    0x68736966206568
]

result = ''.join([hex_value.to_bytes(8, 'little').decode() for hex_value in hex_values])

print("Solved:", result)
```

```bash
$ python level2.py
Solved: Thanks for all the fish
```

![Final Result Frida](/assets/images/result_uncrackable_level2.png)

Thanks for following along! Cheers 🍺
