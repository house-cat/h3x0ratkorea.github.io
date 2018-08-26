---
layout: post
title: Daddy, My MIPS machine works wrong!!
---
[TOC]

# 들어가며

> 우리는 대부분 눈에 보이는 것만이 진실이며 눈에 보이는 것만 믿으려는 경향이 있다.

개인적으로 해커에게 '증명'이란것은 매우 중요하다고 생각 한다.
별게 아닐 주제일 수도 있겠지만, 이런 사소한 것들 하나까지 상세히 증명을 하지 못한다면 그 별것이 아닌것도 내 지식이 되지 않은 것 같기에 이렇게 증명 해 본다.



# 문제점

어느 워게임 사이트의 어떠한 문제(**mips**, elf)를 풀며 의아했던 점이 있었다.

1. 일반적인 PAGE_SIZE(ex: 4kb) 단위로 세그먼트가 나누어져 있지 않았다.
2. checksec의 구현에 따라 바이너리가 (pwntools, gdb-peda, checksec.sh) NX-bit를 사용 하는지에 대한 결과가 달랐다.
3. 실제로 NX-bit가 적용 되는 페이지가 달랐다.

아무리 생각 해도 내 머리로는 해답이 나오지 않아서 멘토님과 대화를 나누며 세가지 문제점이 연관되어 있을 수도 있다는 힌트를 얻었다.

기본적으로 어떠한 요인으로 인해 커널에서 잘못된 매핑이 될 경우 충분히 NX-bit가 깨질 수 있다는 가정을 하고 접근을 시작 했다.



# 실험

## PAGE_SIZE

### mmap length test

```c
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#define ADDR 0x55555000

void main(void){

	void *ptr;

	ptr = mmap((void*)ADDR, 0x100, 3, MAP_ANON|MAP_PRIVATE|MAP_FIXED, 0, 0);
	fprintf(stderr, "OK %p\n",ptr);

	memset(ptr,0xff,0x100);
	fprintf(stderr, "OK memcpy len 0x100\n");

	memset(ptr,0xff,0x1000);
	fprintf(stderr, "OK memcpy len 0x1000\n");

	memset(ptr,0xff,0x1001);
	fprintf(stderr, "OK memcpy len 0x1001\n");

}
```

mmap시 len값을 1kb보다 작은 값을 주고 세가지 테스트를 실행 한다.

`memset(ptr,0xff,0x100);` 은 mmap이 제대로 할당 되었는지에 대해 확인 한다.
`memset(ptr,0xff,0x1000);` 은 mmap이 default PAGE_SIZE만큼 할당 되었는지 확인 한다.
`memset(ptr,0xff,0x1001);` 은 mmap이 default_PAGE_SIZE만큼 할당 되었는지 확인 한다.

qemu를 붙여 실행 해 보았다.

```bash
$ qemu-mips -L /usr/mips-linux-gnu/ ./mmap_len_test
OK 0x55555000
OK memcpy len 0x100
OK memcpy len 0x1000
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
Segmentation fault (core dumped)
```

len을 0x100만큼 줘도 할당이 PAGE_SIZE만큼 제대로 할당 되었음을 확인 했다.



### mmap start test

```c
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#define ADDR 0x55555500

void main(void){

	void *ptr;

	ptr = mmap((void*)ADDR, 0x1000, 3, MAP_ANON|MAP_PRIVATE, 0, 0);
	fprintf(stderr, "OK %p\n",ptr);

	memset(ptr,0xff,0x100);
	fprintf(stderr, "OK memcpy len 0x100\n");

	memset(ptr,0xff,0x1000);
	fprintf(stderr, "OK memcpy len 0x1000\n");

	memset(ptr,0xff,0x1001);
	fprintf(stderr, "OK memcpy len 0x1001\n");

}
```

바뀐 점이라면 ADDR를 0x55555500과 같이 PAGE_SIZE에 맞지 않게 선언 하고, MAP_FIXED 옵션을 뺐다.

> MAP_FIXED옵션은 ADDR값이 PAGE_SIZE의 배수가 아닐 경우 -1을 반환 한다.

```bash
$ qemu-mips -L /usr/mips-linux-gnu/ ./mmap_start_test
OK 0x55555000
OK memcpy len 0x100
OK memcpy len 0x1000
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
Segmentation fault (core dumped)
```

결과는 보는 바와 같이 똑같다.
`void *start`값을 제대로 주지 않아도 0xfffff000과 and 연산을 한 주소에 PAGE_SIZE만큼 할당 한다.



## Page nx bit test

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

char sc[] = { 
        "\x28\x06\xff\xff"        /* slti    a2,zero,-1   */
        "\x3c\x0f\x2f\x2f"        /* lui     t7,0x2f2f    */
        "\x35\xef\x62\x69"        /* ori     t7,t7,0x6269 */
        "\xaf\xaf\xff\xf4"        /* sw      t7,-12(sp)   */
        "\x3c\x0e\x6e\x2f"        /* lui     t6,0x6e2f    */
        "\x35\xce\x73\x68"        /* ori     t6,t6,0x7368 */
        "\xaf\xae\xff\xf8"        /* sw      t6,-8(sp)    */
        "\xaf\xa0\xff\xfc"        /* sw      zero,-4(sp)  */
        "\x27\xa4\xff\xf4"        /* addiu   a0,sp,-12    */
        "\x28\x05\xff\xff"        /* slti    a1,zero,-1   */
        "\x24\x02\x0f\xab"        /* li      v0,4011      */
        "\x01\x01\x01\x0c"        /* syscall 0x40404      */
};

void main(void)
{
       void(*s)(void);
       s = mmap(0, 0x1000, 3, MAP_ANON|MAP_PRIVATE, 0, 0);
       memcpy(s,sc,48);
       s();
}
```

mips shellcode를 mmap한 주소에 복사 하여 실행 한다.

주목 해야 할 점은, 컴파일 옵션에 `-z execstack`을 주지 않았다는 점이다.

```bash
$ mips-linux-gnu-gcc -o mmap_rw mmap_rw.c
$ /opt/checksec.sh/checksec --file ./mmap_rw
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols	   
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   79 
```

보는것과 같이 NX enabled된 바이너리를 실행 하면 상식적으로는 `s()`를 할 경우 바로 Segmentation Fault를 내야 한다.

하지만 실행 결과는 내 눈을 놀라게 했다.

```shell
$ qemu-mips -L /usr/mips-linux-gnu/ ./mmap_rw
# ls
mmap_rw  mmap_rw.c
# whoami
root
# echo WOW
WOW
# exit
```

놀랍게도, 쉘이 실행 되었다.

nx-bit가 적용 되어 있지 않은것이다.



## 실험 결과

mmap의 PAGE_SIZE와 관련된 문제는 없었다.
다만, nx-bit가 제대로 적용 되어 있지 않음을 발견 했다.



# 분석

## PAGE_SIZE 문제

위의 실험 결과에서도 볼 수 있듯이, CPU별로 선언된 PAGE_SIZE만큼 페이징을 하는것은 맞다.
그렇다면, ELF의 모든 섹션을 연속된 메모리 주소 공간에 mmap 할 수 있음을 알 수 있다.

그래서 1번 문제점은 해결 했다.



## mips_elf_read_implies_exec

리눅스 커널 소스의 [elf.c](https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips/kernel/elf.c#L329) 를 확인 해 보면

```c
...
int mips_elf_read_implies_exec(void *elf_ex, int exstack)
{
	if (exstack != EXSTACK_DISABLE_X) {
		/* The binary doesn't request a non-executable stack */
		return 1;
	}

	if (!cpu_has_rixi) {
		/* The CPU doesn't support non-executable memory */
		return 1;
	}

	return 0;
}
...
```

다음과 같은 코드를 찾을 수 있다.
한가지 추측 할 수 있는 점은, MIPS는 cpu별로 nx-bit를 설정 할 수 있는지에 대한 여부가 달라 진다는 것이다.

cpu_has_rixi를 따라가며 분석을 해 보자.



## cpu_has_rixi

[cpu-features.h](https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips/include/asm/cpu-features.h#L156) 를 한번 확인 해 보자.

```c
...
#ifndef cpu_has_rixi
#define cpu_has_rixi		(cpu_data[0].options & MIPS_CPU_RIXI)
#endif
...
```

cpu_data[0].options와 MIPS_CPU_RIXI flag를 and 연산의 결과가 cpu_has_rixi다.

그렇다면 cpu_data[0].options의 값을 세팅 하는 부분을 따라 가 보자.
[decode_configs](https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips/kernel/cpu-probe.c#L865)
[decode_config3](https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips/kernel/cpu-probe.c#L709)

```c
...
if (config3 & MIPS_CONF3_RXI)
	c->options |= MIPS_CPU_RIXI;
...
```

[MIPS_CONF3_RXI](https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips/include/asm/mipsregs.h#L618) 플래그가 세팅 되어 있을 시 cpudata[0].options의 MIPS_CPU_RIXI 플래그를 세팅 한다.



바로 몇라인 위에서 [config3](https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips/kernel/cpu-probe.c#L703) 을 [read_c0_config3()](https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips/include/asm/mipsregs.h#L1663) 매크로를 이용 해 세팅 한다.

```c
...
    #define read_c0_config3()	__read_32bit_c0_register($16, 3)
...
```



해당 매크로는 [___read_32bit_c0_register()](https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips/include/asm/mipsregs.h#L1337) 매크로를 사용 하고 있으며, 다음과 같다

```c
#define ___read_32bit_c0_register(source, sel, vol)			\
({ unsigned int __res;							\
	if (sel == 0)							\
		__asm__ vol(						\
			"mfc0\t%0, " #source "\n\t"			\
			: "=r" (__res));				\
	else								\
		__asm__ vol(						\
			".set\tmips32\n\t"				\
			"mfc0\t%0, " #source ", " #sel "\n\t"		\
			".set\tmips0\n\t"				\
			: "=r" (__res));				\
	__res;								\
})
```



### Coprocessor 0 register

mips에는 coprocessor(협동프로세서? 보조프로세서? 정도로 해석하면 되겠다.)란게 존재 하는데, 1번 coprocessor는 fpu와 같이 소수점 연산에 쓰이며 0번 coprocessor는 interrupt와 exception처리에 쓰인다.

이 레지스터는 mfc0이란 명령어를 이용 해 불러 올 수 있다.

이중 16번 레지스터는 Configuration register로 쓰이고, 또 그중 3번 선택 레지스터(Config3)가 NX-bit와 관련된 정보를 담고 있다.

그래서 위 코드의 `mfc0 %0, #source, #sel`은 `mfc0 %0, $16, 3`으로 바뀔 수 있고, 16번 레지스터에서 3번 선택 레지스터를 읽어 저장 한다.



### Config3 register

| Name | BIts | Description                                                  |
| ---- | ---- | ------------------------------------------------------------ |
| M    | 31   | This bit is reserved to indicate that a Config4 register is present. With the current architectural definition, this bit should always read as a 0. |
| 0    | 30:2 | Must be  written as zeros; returns zeros on read             |
| SM   | 1    | SmartMIPS™ ASE implemented. This bit indicates whether the SmartMIPS ASE is implemented. |
| TL   | 0    | Trace Logic implemented. This bit indicates whether PC or data trace is implemented. |

이중 SM bit가 SmartMIPS를 호환하고 있는지에 대한 내용이다.

이제 슬슬 결론에 도달 하고 있는 느낌이 오기 시작 한다.



## NX-bit : SmartMIPS Implemention

[SmartMIPS](https://www.linux-mips.org/wiki/SmartMIPS)란 MIPS의 확장 기능인데, [스마트카드](https://ko.wikipedia.org/wiki/%EC%8A%A4%EB%A7%88%ED%8A%B8%EC%B9%B4%EB%93%9C)의 보안을 위해 개발 되었다.
그중 중요 기능중 한가지가 바로 NX-bit다.

> New TLB bits allow disabling execute permission of readable pages and pages that are writable but not readable.

여기서 MMU레지스터의 TLB에는 Page Table Entry가 들어 가는데, 보통 PTE에 RWX 비트로 페이지 권한을 설정 할 수 있다.

이 말인 즉슨 SmartMIPS를 호환하고 있지 않다면, 아마 대부분의 MIPS CPU에서는 Shellcode를 이용한 공격이 가능할 가능성이 높다.



# 추가 연구 주제

### qemu-mips의 SmartMIPS Implemention

qemu-mips의 지원하는 cpu중 SmartMIPS Implemention의 개발 및 분석이 필요하다.



### mips 아키텍처에서의 Software단의 NX-bit 구현

예시로 레드햇의 Exec Shield라는 프로젝트가 존재 한다.
Exec Shield는 32비트 x86 cpu들에서 NX기능을 활용 하기 위해 만들어 졌다.

Exec Shield를 예로 삼고 MIPS만의 Exec Shield의 개발이 필요하다.



# 결론

**Mips에서 NX-bit가 사용 가능 한 것처럼 보이지만, CPU의 SmartMIPS를 호환해야 사용 가능 하다.**

여담이지만 지금까지 커널 공부를 하며 '왜' 인지, 즉 근원을 쫓아가며 생각하고 공부 해 본적은 처음같다.
열심히 공부하여 정리한 이 글이 누군가에게 도움이 되면 좋겠다.



# References

https://elixir.bootlin.com/linux/v4.18.5/source/arch/mips

https://ko.wikipedia.org/wiki/%ED%8E%98%EC%9D%B4%EC%A7%80_%ED%85%8C%EC%9D%B4%EB%B8%94

https://github.com/ulli-kroll/linux-comcerto/blob/master/arch/mips/include/asm/pgtable-bits.h

https://android.googlesource.com/kernel/goldfish/+/android-3.18/arch/mips/include/asm/pgtable-bits.h?autodive=0%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F

https://www.linux-mips.org/archives/linux-mips/2015-07/msg00348.html

https://www.programering.com/a/MDM1MTNwATc.html

http://www.cs.cornell.edu/courses/cs3410/2008fa/MIPS_Vol3.pdf

https://www.linux-mips.org/wiki/SmartMIPS

https://en.wikipedia.org/wiki/Smart_card

http://hotpotato.tistory.com/282

https://ko.wikipedia.org/wiki/%EC%8B%A4%ED%96%89_%EA%B0%80%EB%8A%A5_%EA%B3%B5%EA%B0%84_%EB%B3%B4%ED%98%B8
