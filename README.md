# Challenges

Writeups of the challenges in the [OPKoKo CTF](https://opkoko.quest/) that was held in Berlin from 2023-05-18 until 2023-05-20.

![scoreboard](Images/scoreboard.png)

## **Fledermaus**

The flag is written in dingbats, where each symbol represents an ascii character.

**Solution:**  

Use an online decoder
[https://www.dcode.fr/itc-zapf-dingbats](https://www.dcode.fr/itc-zapf-dingbats)

Flag: `OP{th4ts_fr3ak1n_b4ts}`

## Only humans allowed
We have a flag for you but we had to hide it from the robots 🤖 I'm sure you can find it.

**Solution:**  

Check the `/robots.txt` file [https://opkoko.quest/robots.txt](https://opkoko.quest/robots.txt)

The path `/gyrf9g7l64` is disallowed. 

Visit [https://opkoko.quest/gyrf9g7l64](https://opkoko.quest/gyrf9g7l64) and you get the flag.

Flag: `OP{r0B0t_0v3Rl0rdZ}`

## Due Diligence
I was looking to invest in this cool new startup but heard rumors that they're involved with some black hat hackers. Can you find out who and what they're planning?

**Solution:**  

The [tweet](https://twitter.com/vocro_corp/status/1651261547929387020) on the profile has a reply from [@sam_bauer90](https://www.instagram.com/p/CsEd86hKuQE/).  @sam_bauer90 has a tweet with a link to his Instagram, on the Instagram there is another post with the Vocro Corp logo with the location set to [Super Secret Underground Bunker](https://www.instagram.com/explore/locations/229426160413805/super-secret-underground-bunker/).  
Click the location to see other posts from the same location. One of them is by the user cryptid.iso, referencing hacking. On their profile is an image with their Github username visible [electrocryptid](https://github.com/electrocryptid/secret-notes/commit/747099c3ce9fffcc4054400aca4c0d354abb55df).  
Visit the Github profile for electrocryptid and there will be a repo called secret-notes. In the commit history there is a commit with the message ‘Add secret note’ with the flag.

Flag: `OP{pr0f3ssi0n4l_st4lk3r}`

## IT-Support
We found this old router but we don’t know the WiFi password, can you help us find it?

**Solution:**  

Extract the firmware to get the filesystem, a suggested tool is `firmware-mod-kit`.  
Search the files for any mention of `password`. The file `www/bsc_wlan.php` contains `$def_password =“T1B7ZDBudF9oNHJkYzBkM19jcjNkc30=“;`.  
Base64 decode the value and you get the flag.

```
firmware-mod-kit/extract-firmware.sh firmware.bin 
grep -ir password 
T1B7ZDBudF9oNHJkYzBkM19jcjNkc30= | base64 -d
```

Flag: `OP{d0nt_h4rdc0d3_cr3ds}`

## Katze Vermisst
Can you please find my cat?

![Untitled](Images/Untitled.png)  

**Solution:**  
Call the number on the poster and wait for voicemail. Write down the flag that is said in german.  

Flag: `OP{TH3_C4T_15_BACK}`

## Big In Japan

This is a puzzle called nonogram.

![nonogram-op.png](Images/nonogram-op.png)

**Solution:**  
When the nonogram is solved, it will reveal a QR code that can be scanned to get the flag. The rules for how you solve these puzzles can be found [here](https://puzzlygame.com/pages/how_to_play_nonograms/).

![qr.png](Images/qr.png)

Flag: `OP{OPKoKoTokyo}`

## ROuTe to 1337
I have a very cryptic colleague here at KoKo who wont leave me alone, keeps repeating the phrase "b32x2xb64" without explaining themselves. This person is saying they are 1337 over and over again and keep following me around. They gave me this weird looking text string and told me that I too could be LEET if I manage to decode it. Could you help me figure out what they are talking about?

**Solution:**

1. Open cyberchef: https://gchq.github.io/CyberChef/
2. Paste the string `JJKVSVSFGRFUUSKOGRDUSVSLIREUUVSWJ4ZUWQSNGVGEIQZUIRBEWWSXIZCVOU2WJZDEERSFKYZU2R2CKRLESUJSINFUUTCEIE3EGVCKJZKFONSTGJHUSTSCI5GVMSSSJNFE4RSNGJFUGS2WJVEFGUKTKZGEEVKVIVKVGWSJLFMVOTKWJJJESSSTIVJVESS2JVDE2V2ZGIZUQSSKJVCVGUZTIVHTKWKEI5ITGT2NJZDFOSJVGNIUOTSCK42FSMSMJVJDGWCBJUZEITS2KJKVOWSELBHUCWSVI4ZVIRCKJZJUQTZUIJKESTSYI5DVGM2FJ42VSRCHKEZU6TKOIZLUSNJTKFDU4QSXGRMTETCNKIZVQQKNGJCE4WSSKVLVURCYJY2TKRSLKJJFES2GIVKU2VKUI5FEMRCGIVNEWS2LIZMFITKULJJUYSJUKZHVETCRI5NEUVZUJVFVSS2CLBDVSUZSK5DU4NCEKFJUYTCPIJHEOS2WGJFE6RSRK5JTIRCQ` into input.
3. Select "from base32" from operators.
4. Select "from base32" again from operators.
5. Select "from base64".
6. Lastly, select the operator "rot47" and put 1337 in the "amount" field to get the flag.

[Solution cyberchef](https://cyberchef.org/#recipe=From_Base32('A-Z2-7%3D',true)From_Base32('A-Z2-7%3D',true)From_Base64('A-Za-z0-9%2B/%3D',true,false)ROT47(1337)&input=SkpLVlNWU0ZHUkZVVVNLT0dSRFVTVlNMSVJFVVVWU1dKNFpVV1FTTkdWR0VJUVpVSVJCRVdXU1hJWkNWT1UyV0paREVFUlNGS1laVTJSMkNLUkxFU1VKU0lORlVVVENFSUUzRUdWQ0tKWktGT05TVEdKSFVTVFNDSTVHVk1TU1NKTkZFNFJTTkdKRlVHUzJXSlZFRkdVS1RLWkdFRVZLVklWS1ZHV1NKTEZNVk9US1dKSkpFU1NTVElWSlZFU1MySlZERTJWMlpHSVpVUVNTS0pWQ1ZHVVpUSVZIVEtXS0VJNUlUR1QyTkpaREZPU0pWR05JVU9UU0NLNDJGU01TTUpWSkRHV0NCSlVaRUlUUzJLSktWT1dTRUxCSFVDV1NWSTRaVklSQ0tKWkpVUVRaVUlKS0VTVFNZSTVEVkdNMkZKNDJWU1JDSEtFWlU2VEtPSVpMVVNOSlRLRkRVNFFTWEdSTVRFVENOS0laVlFRS05HSkNFNFdTU0tWTFZVUkNZSlkyVEtSU0xLSkpGRVMyR0lWS1UyVktVSTVGRU1SQ0dJVk5FV1MyTElaTUZJVEtVTEpKVVlTSlVLWkhWRVRDUkk1TkVVVlpVSlZGVlNTMkNMQkRWU1VaU0s1RFU0TkNFS0ZKVVlUQ1BJSkhFT1MyV0dKRkU2UlNSSzVKVElSQ1E)

Flag: `OP{4m_1_4lS0_l337_n0w?!?}`

## Lockpicking Lawyer
Can you open the lock?

**Solution:**  
Pick the lock and get the flag.  

Flag: `OP{b0snian_bill}`

## Dystopia
I asked my friends at my local book club if I could borrow their favourite book. They told me no, that I'm not allowed to read George.. OhWell!
A couple of days later, the people at the book club felt bad and told me that they had made some changes to the classic literature and handed me this weird looking text. Could you help me figure out what it is?

**Solution:**  
Frequency analysis will reveal that the text is from George Orwell's novel 1984. Use a [tool](https://www.guballa.de/substitution-solver) or manually substitute the letters to reveal the flag in the text.

Flag: `OP{B1G_BR0TH3R_1S_W4TCH1NG_Y0U}`

## Double Trouble
Can you open 2 locks?

**Solution:**  
Pick the lock and get the flag.  

Flag: `OP{n0t_4_fluke}`

## Hurts My Brain

Brainfuck printed on paper.

```
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>+++++++++.+.>+++++++++++++++++++++++.<++++++++++++++++++++.+++++.-----.-----.>--.<<++++++++++++++++++.>>----.<.>.--.<++++++.------.----------------.------------.+++++++++++++++.<+++++++++++++++.>>++++++++++.
```

**Solution:**
Use OCR or write down the code and run it through a [interpreter online](https://www.dcode.fr/brainfuck-language).  

Flag: `OP{did_y0u_use_OCR?}`

## Versteckspiel
Count to 10 then try to find us.

![place1.jpg](Images/place1.jpg)

![place2.jpg](Images/place2.jpg)

![place3.jpg](Images/place3.jpg)

**Solution:**  
Find the hidden places.

*Place 1*: This part of the flag was hidden in room B92 (floor B) in the gray pocket for remote controls.

*Place 2*: On the bottom floor (floor A) at the other end of the room.

*Place 3*: On the top floor (floor C) under one of the stairs.

Flag: `OP{h1d3_y82_4nd_5fq_s33k_:}`

## Pseudo Random
Challenge made by Simon Johansson.

**Solution:**

After investigation of leaked JWT's:

```
Header:
{
  "alg": "ES256",
  "typ": "JWT"
}

And with claims:
{
  "exp": 1683420911,
  "scopes": [
    "capture"
  ]
}
```

Upon requesting with one of these against the API, we receive "token is expired." The goal is to find a flaw in the authentication/authorization flow, for example, by sending "alg": "none". However, it doesn't seem to help. The challenge is titled "Pseudo Random," can we do something about that?

A signed JWT that uses the ES256 algorithm employs elliptic curves, specifically NIST P-256 (or secp256r1 or prime256v1). This algorithm has a random component, could that be what the title refers to?

A signature consists of two components, r and s. These are a function of the message, random, and the private key. Specifically, the format of this signature is a byte array that is 64 bytes long, where r corresponds to the first 32 bytes and s corresponds to the rest.

In other words,
Signature[64] = { r[32] || s[32] }

A JWT has the format "HEADER.BODY.SIGNATURE" where HEADER, BODY, and SIGNATURE are base64-encoded. If we examine the signature part in the JWTs, we can see that the signature looks very similar in the beginning.

```
1: "pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf4Q-avxcJwsembKUibgpHmvAWml2vmAGTJnnsEpvG-Drw"
2: "pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf7DhYKI5ksm10sp3twPcwZySjDtVkumO48Yg6wzUVYB6w"
3: "pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf7CVPaoTiFWEBp63JaDKF2eU6ZU5xU-XJIIq9SecXFe8g"
```

They appear to start exactly the same: "pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf".
Could it be that the issuer of these tokens has reused the same random value for these tokens?

To decode them, you can do it like this in Python:
```
def b64decode(s):
    return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))

token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODM0MjA5MTEsInNjb3BlcyI6WyJjYXB0dXJlIl19.pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf4Q-avxcJwsembKUibgpHmvAWml2vmAGTJnnsEpvG-Drw"
parts = token.split('.')
signature_bytes = b64decode(token[2])
print(len(signature_bytes))
r = signature_bytes[0:32]
s = signature_bytes[32:]
print(binascii.hexlify(r))
print(binascii.hexlify(s))

```

Here we can clearly see that for the two JWTs that exist, the r value is the same.
```
b'a51912edd1598f0f66c1445af4e683a6466685a9d71c62a76b356bb02f4ec9fe'
b'a51912edd1598f0f66c1445af4e683a6466685a9d71c62a76b356bb02f4ec9fe'
```

But the "s" value seems to differ:  
```
b'10f9abf1709c2c7a66ca5226e0a479af0169a5daf9801932679ec129bc6f83af'
b'c3858288e64b26d74b29dedc0f7306724a30ed564ba63b8f1883ac33515601eb'
```

If the same random value has been used to sign two different messages, we can calculate the private key.
It is well described here:
https://billatnapier.medium.com/ecdsa-weakness-where-nonces-are-reused-2be63856a01a

What is signed in a JWT is: HEADER.BODY, tex:  
```
Message: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODM0MjA5MTEsInNjb3BlcyI6WyJjYXB0dXJlIl19"
Signatur: "pRkS7dFZjw9mwURa9OaDpkZmhanXHGKnazVrsC9Oyf4Q-avxcJwsembKUibgpHmvAWml2vmAGTJnnsEpvG-Drw"
```

Here is a function to calculate the private key based on two messages + signatures:  
```
def extract_private_key(m1, m2, sig1, sig2):

    m1 = normalise_bytes(m1)
    m2 = normalise_bytes(m2)
    h1 = normalise_bytes(sha256(m1).digest())
    h2 = normalise_bytes(sha256(m2).digest())
    h1 = _truncate_and_convert_digest(h1, NIST256p, True)
    h2 = _truncate_and_convert_digest(h2, NIST256p, True)
    r1, s1 = extract_r_s(sig1)
    r2, s2 = extract_r_s(sig2)
    n = NIST256p.order
    d = ((s1*h2 % n - s2*h1 % n) * numbertheory.inverse_mod((s2*r1 % n - s1*r2 % n), n) % n)

    return d, number_to_string(d, NIST256p.order)
```

The function returns the private key as a scalar or as a bytearray. We will use the bytearray:  
```
p, d = extract_private_key(message1, message2, sig1, sig2)
extracted_key = SigningKey.from_string(d, curve=NIST256p, hashfunc=sha256)
# Använder två olika kryptobibliotek här, hittade inte hur jag använde JWK biblioteket för att
# använda skalären/byte arrayen och initiera en nyckel.
extracted_jwk = jwk.JWK.from_pem(extracted_key.to_pem())
```

Then we can create our own JWT that is valid for one hour:  
```
payload = {
    "exp": int(time.time()) + 3600,
    "scopes": [
        "capture"
    ]
}

data = jwt.encode(payload, extracted_jwk.export_to_pem(private_key=True, password=None), algorithm="ES256")
print("Generated extracted JWT")
print(data)
```

Solution to get the flag:  
Go into the folder `solution_pseudo-random`  
Run:  
```
pip install -r requirements.txt
python3 hack_tokens.py
```

Flag: `OP{CrYP70_83Rl1n}`

## DEFAULT
Hint: RFID

**Solution:**  
Mifare Classic 1k - default

Read tag with Android phone using MIFARE Clasic Tool. Standard key `FFFFFFFFFFFF`. Decrypt the hex data to get the key.  

Flag: `OP{d0nt_us3_d3f41t_key5}`

## Keys Keys Keys
This card seems to use multiple keys...

**Solution:**  
Mifare Classic 1k - harder key

Read the first sector and get the key to the next sector. Use an app such as MIFARE Classic Tool on Android and add the new key to a wordlist. Rinse and repeat until you decrypt the last sector where you will find the flag. The following keys were used:

```
FFFFFFFFFFFF
112233445566
AABBCCDDEEFF
A0A1A2A3A4A5
B0B1B2B3B4B5
4B0B20107CCB
204752454154
ACFFFFFFFFFF
6471A5EF2D1A
DEADBEEEEEEF
B000000000B5
123987AB45AA
ABCDEF646464
BEEFBEEFBEEF
133337ABCDEF
```

Flag: `OP{keys_are_evil}`

## Matryoshka


**Solution:**
Mifare Classic 1k - Encrypted ZIP-file

Contents of the card:
```
hf mf csetblk --blk 4 -d 504b0304140009000800f8445a55f3e5
hf mf csetblk --blk 5 -d 286445010000b901000009001c00666c
hf mf csetblk --blk 6 -d 61672e6a706567555409000353f25863
hf mf csetblk --blk 8 -d 55f2586375780b000104e803000004e8
hf mf csetblk --blk 9 -d 0300005d6f4d41ac16e036bb5dd8b98a
hf mf csetblk --blk 10 -d 6b1087c9b37e0f1465747d290105824f
hf mf csetblk --blk 12 -d 49e60915e45b6c9d8fcaf86bfef7087b
hf mf csetblk --blk 13 -d 66d30f87261950fb36898e4219b11718
hf mf csetblk --blk 14 -d 9a1ab1c6494c1cf906d4b73243c857ba
hf mf csetblk --blk 16 -d d2ea2d179e21a8703f1ae6f39d91a1ba
hf mf csetblk --blk 17 -d afd784a8e8d895497d75ed509c975a58
hf mf csetblk --blk 18 -d 62297f5fbf9e86303b663ce0213a5d52
hf mf csetblk --blk 20 -d 397d105c3216c2456aa3fb3022a2f2d9
hf mf csetblk --blk 21 -d 274b77bdb6d1429de52f7ddc427d2815
hf mf csetblk --blk 22 -d a955369cd14318789be02e98d58e7259
hf mf csetblk --blk 24 -d e9347499a6a538dcf13f0d33482e716b
hf mf csetblk --blk 25 -d a248722466f519cb1c1e38ad180cb919
hf mf csetblk --blk 26 -d 9ebdb85d18df73711d7bbcfed3b6e472
hf mf csetblk --blk 28 -d 0e98cd504f14adb9f0f1eea319ad59b1
hf mf csetblk --blk 29 -d 89302ca0116a49fed9fe7cbb41380f6e
hf mf csetblk --blk 30 -d 3fc7ca56e32ed4cfaa072e1fee251335
hf mf csetblk --blk 32 -d b8b2cd1a1c9b664f29b45ac192ee3f42
hf mf csetblk --blk 33 -d 251df78df561718cb7616c74eadaa13a
hf mf csetblk --blk 34 -d f45e156849ecd6baa7a226093525bb78
hf mf csetblk --blk 36 -d da32d42c8ea8955f504b0708f3e52864
hf mf csetblk --blk 37 -d 45010000b9010000504b01021e031400
hf mf csetblk --blk 38 -d 09000800f8445a55f3e5286445010000
hf mf csetblk --blk 40 -d b9010000090018000000000000000000
hf mf csetblk --blk 41 -d a48100000000666c61672e6a70656755
hf mf csetblk --blk 42 -d 5405000353f2586375780b000104e803
hf mf csetblk --blk 44 -d 000004e8030000504b05060000000001
hf mf csetblk --blk 45 -d 0001004f000000980100000000000000
```

First read the Mifare Classic 1k card and dump the contents.  
When put together this assembles an encrypted ZIP file with the password `(omega)` that is available in rockyou (sorry!).
The file `flag.jpeg` contains hex data in the `Artist` and `Comment` field. When `base64` decoded you get the flag.  

Flag: `OP{cracking_makes_computer_go_brrr}`

## Wrapper's Delight
I created a neat website for people to contact me, and I'm certain it's 100% secure.
Good luck trying to hack me 😎

**Solution:**  
1. See that the path parameter in the URL is vulnerable to LFI
2. See in `/robots.txt` an interesting PHP file which would be interesting to see through the LFI, but the webserver will just execute the PHP code so you cannot see the source directly through LFI.
3. Use the PHP filter wrapper to encode the file contents, i.e., base64 and see the flag in the admin.php file.
File wrapper: `php://filter/convert.base64-encode/resource=secretstuff/admin.php`

Flag: `OP{LF1_B3_g0N3_pL3453}`

## trollolololol
Eduard Chil is my favourite singer. I really love the lyrics of the song he's most known for.

**Solution:**  
1. Open cyberchef: https://gchq.github.io/CyberChef/
2. Paste the string of trololo... into input.
3. Select replace from operators, replace "tr" with blank.
4. Select replace again and replace "o" with "0"
5. Select replace a third time and replace "l" with "1"
6. Lastly, select the operator "from binary" to get the flag.

[Solution cyberchef](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'tr'%7D,'',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'o'%7D,'0',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'l'%7D,'1',true,false,true,false)From_Binary('Space',8)&input=dHJvbG9vbGxsbCB0cm9sb2xvb29vIHRyb2xsbGxvbGwgdHJvbGxvb29sbyB0cm9vbGxvb29sIHRyb2xsb2xsbG8gdHJvb2xsb2xvbyB0cm9sbGxvb2xvIHRyb2xsbGxvb2wgdHJvbG9sbGxsbCB0cm9vbGxvb29sIHRyb2xsbG9vbGwgdHJvbG9sbGxsbCB0cm9sbGxsb29sIHRyb29sbG9vb28gdHJvbGxsb2xvbCB0cm9sb2xvb2xvIHRyb2xvbGxsbGwgdHJvbG9vb29sbyB0cm9vbGxvb2xsIHRyb2xsbGxvbG8gdHJvbG9sb2xvbyB0cm9sb2xsbGxsIHRyb2xsb29sbG8gdHJvbGxsb29sbyB0cm9vbGxvb29sIHRyb29sbG9vbGwgdHJvbGxvbGxsbyB0cm9sb29vbG9vIHRyb2xsbGxsb2w)


Flag: `OP{b1n4ry_1s_y0uR_B3zT_fr13nD}`

## Das Firmenbild
Some company sent me a picture of their logo. It seems like something's weird with it, can you please help me?

**Solution:**

You get two files:
- file.txt
- omegapoint.jpg

Type the following to decode the base64 or decode the string in the file.txt in [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=YjIxbFoyRndiMmx1ZEc5d2EyOXJiMmx1WW1WeWJHbHVNakF5TXc9PQo)  
`cat file.txt | base64 -d`  
And you'll get `omegapointopkokoinberlin2023`

Download steghide and run the following command:
`steghide extract -sf omegapoint.jpg -p omegapointopkokoinberlin2023`

You'll notice that you extracted a hidden file called flag.txt  
Open it and you have the flag.

Flag: `OP{ooH_yOu_fOunD_mE}`

## Sanity Check
Stop slacking and find the flag instead

**Solution**
Open the slack channel `opkoko-ctf` and you'll find the flag in the channel's topic.

Flag: `OP{W3lcom3_tO_b3rLiN}`

## The Brutal Zip
I encrypted my zip file yesterday but forgot the password, you rock if you help me figure it out!

**Solution**  
When you try to unzip the zip you'll notice that it requries a passphrase.  
You need to bruteforce it by using the wordlist [rockyou.txt](https://www.google.com/search?client=firefox-b-d&q=rockyou.txt+)  
Download john the ripper password cracking tool.

Run:  
`zip2john 53cr3t.zip > hash.txt`  
To get a hash value from the zip and add into a file called hash.txt

Run:  
`john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`  
To bruteforce the hash to get the password which is `bypass1512`  

Unzip the `53cr3t.zip` with the passphrase `bypass1512`  
And you'll get the flag.

Flag: `OP{wow_you_guessed_it_right}`


## qroken
This seems broken...

![broken.png](Images/broken.png)

**Solution:**  
Draw the required pixels to fix the QR code. These pixels are standardized for every QR code of this size. Scan the QR code for the flag.  

![original.png](Images/original.png)

Flag: `OP{klipp_0ch_klistra}`

## **In Plain Sight**
I received this strange binary that seems to do nothing.. Could you help me find out what it does?

**Solution:**  

Unzip the zip and you'll get a folder with two different binaries.  
Run `strings` on any of the files and you'll get the flag.

`strings ./in_plain_sight`

Flag: `OP{h1d1ng_1n_pla1n_s1gh7}`

## 1Password
It is recommeded to use a password manager. Do you know which one Omegapoint recommends you to use?

**Solution:**  
The flag is hidden in the shared Omegapoint vault in 1Password.  
Login to the Omegapoint 1Password account and get the flag in the note.  

![Untitled](Images/Untitled%201.png)

Flag: `OP{Summer2023_here_we_go}`

## Red Dragon
Can you help me find out what is going on with this executable?

**Solution:**  
[https://gchq.github.io/CyberChef/#recipe=From_Hex('None')XOR({'option':'Latin1','string':'OPk0k0'},'Standard',false)&input=MDAwMDEwNTQ1ODA3MTA2MzE5NmYwMDQ1MjMwZjA2MDMwZjZmMGMwNDJkMTExNg](https://gchq.github.io/CyberChef/#recipe=From_Hex('None')XOR(%7B'option':'Latin1','string':'OPk0k0'%7D,'Standard',false)&input=MDAwMDEwNTQ1ODA3MTA2MzE5NmYwMDQ1MjMwZjA2MDMwZjZmMGMwNDJkMTExNg)

Flag: `OP{d37_3r_kul_m3d_CTF!}`

## Dynamic
This challenge is trying to find out what I'm up to, can you help me find out if it is spyware?

**Solution:**  
1. Run the binary, enter the option to "hacktheplanet", nothing happens.
2. Do som dynamic analysis, use the strace command line utility to see that a POST request is being made when entering `3.hacktheplanet`.
3. Use wireshark to see what is being posted, in the post body there will be a Base64 encoded string with the flag contents

Flag: `OP{Tr4fF1C_Sn1Ff1Ng_4nd_DynAm1c_4n4ly515_f7W}`

## Zip Zip Zip
Do you have what it takes?

Hint: berlin

**Solution:**
Write a script that unzips the file 500 times with the password `berlin`

```
#!/bin/bash

for i in {500..0}
do
	/usr/bin/unzip -P "berlin" "flag_$i.zip"
	/usr/bin/rm "flag_$i.zip"
done
```

Flag: `OP{7h475_4107_0F_Z1P5}`

## The Pink Panther
This looks easy

**Solution:**  
Pick the lock and get the flag.  

Flag: `OP{h4rder_th4n_it_looks}`
