---
layout: post
title: YISF 2018 PREQUALIFY Forensic 200 write-up
---

대회 당시엔 0 솔버였던 문제...

~~사실 쓸 생각 없었는데 팀 블로그에 쓸 목적으로 써봄~~

솔직하게 이야기 하자면 포렌식 치고는 개연성이 좀 약했던 문제,,

준 E01 파일을 보면 파티션이 2개 잡혀 있는데, 1개는 시스템 예약 파티션이고, 한개는 윈도우가 설치된 파티션입니다.

하지만 볼륨 전체를 보면 이 두 파티션 뒤에 UnAllocated Space 가 있으며, 약 2메가의 데이터와 그 뒤에 FAT32 파티션이 있습니다.

FAT32 파티션을 열어보면 Secret 폴더에 keyfile.jpg 가 있으며, 이를 VeraCrypt의 Keyfile로 설정하여 주고, 앞서 언급한 2메가의 데이터를 카빙하여 저장후 마운트 하면 정상적으로 마운트가 되고, 파일 3개가 나옵니다.

![](https://raw.githubusercontent.com/h3x0ratkorea/h3x0ratkorea.github.io/master/content/Result__.png)

실행시켜주면 플래그 Get!

![](https://raw.githubusercontent.com/h3x0ratkorea/h3x0ratkorea.github.io/master/content/Result....png)
