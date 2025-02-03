# decode_clamav_sig_utf8
Decode ClamAV Signatures to UTF-8

So, I wrote this because when you decode ClamAV signatures with ClamAV's sigtool, the signatures are still represented as Hexcode. But since many Virus-Signatures actually match ASCII/UTF8 strings inside the infected file / executable, it is, in order to understand how an antivirus program works, very interesting to see which strings are matched by the signatures. This is tedious to do by hand, because ClamAV signatures have many special characters inbetween the hex, which lets many hex-to-binary programs you might want to use derail (like xxd). Therefore I wrote this program, which does all that for you and tries to display the Signatures in a format that is much easier for humans to read.  
If you are interested, here is the documentation of the ClamAV signature formats. You might want to read that in order to know what the special patterns like ":w" mean, which decode_clamav_sig_utf8 puts on a new lines in an effort to make them distinguishable from the decoded hex:  
https://docs.clamav.net/manual/Signatures.html  
https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html  
https://docs.clamav.net/manual/Signatures/LogicalSignatures.html

# Howto

Compile:  
`go build decode_clamav_sig_utf8.go`

Then, unpack the ClamAV databases with ClamAV's sigtool:  
`cd ~/folder/for/signatures`  
`sigtool -u /var/lib/clamav/main.cvd`  
`sigtool -u /var/lib/clamav/daily.cvd`

Now, you can use decode_clamav_sig_utf8 to take a look at them. You just pipe the text into decode_clamav_sig_utf8, like this:  
`cat daily.ldb | ./decode_clamav_sig_utf8 ldb | less`  
The Syntax is:  
`cat main.[ldb|ldu|ndb|ndu] | decode_clamav_to_utf8 [ldb|ldu|ndb|ndu]`  
Only the ldb, ldu, ndb and ndu files can be decoded.

# Example

Let's say ClamAV has flagged a file as `Win.Dropper.Havex-9967324-0` and you would like to know why it did flag the file. You could search for it in the signatures and what you would find is this:  
`grep 'Win.Dropper.Havex-9967324-0' *`  
`daily.ldb:Win.Dropper.Havex-9967324-0;Engine:81-255,Target:1;0&1&2&3&4;6e7374616c6c2053797374656d2076332e3061313c2f6465736372697074696f6e3e3c7472757374496e666f20786d6c6e733d2275726e3a736368656d61732d6d6963726f736f66742d636f6d3a61736d2e7633223e3c73656375726974793e3c72657175657374656450726976696c656765733e3c7265717565737465;4d4220436f6e6e656374204c696e6520476d6248::w;2a207e68643d;472563542546;3157715d254e512562`

But who is supposed to understand that? Now, we use decode_clamav_sig_utf8 (which I realize is a very bad name, but whatever) to make it more readable:  
`grep -i 'in.Dropper.Havex-9967324-0' daily.ldb | decode_clamav_sig_utf8 ldb`
```
Signature Name           : Win.Dropper.Havex-9967324-0
Target Description Block : Engine:81-255,Target:1
Logical Expression       : 0&1&2&3&4
Subsignature 0:
nstall System v3.0a1</description><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requeste
original_hex(6e7374616c6c2053797374656d2076332e3061313c2f6465736372697074696f6e3e3c7472757374496e666f20786d6c6e733d2275726e3a736368656d61732d6d6963726f736f66742d636f6d3a61736d2e7633223e3c73656375726974793e3c72657175657374656450726976696c656765733e3c7265717565737465)
Subsignature 1:
MB Connect Line GmbH
original_hex(4d4220436f6e6e656374204c696e6520476d6248)
::w
Subsignature 2:
* ~hd=
original_hex(2a207e68643d)
Subsignature 3:
G%cT%F
original_hex(472563542546)
Subsignature 4:
1Wq]%NQ%b
original_hex(3157715d254e512562)
```

Now, this makes a lot more sense. ClamAV only looks for five strings in PE executables (Target:1 = PE executable) and if these five strings are in the file, it gets flagged. Many antivirus programs work like this. This "grep on steroids" is the bread and butter of endpoint antivirus programs and you learn a lot by studying even something as accessible as ClamAV.