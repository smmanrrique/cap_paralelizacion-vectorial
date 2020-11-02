
scale_shift.1k.single.vec.avx.gcc:     file format elf64-x86-64


Disassembly of section .init:

0000000000400470 <_init>:
  400470:	48 83 ec 08          	sub    $0x8,%rsp
  400474:	48 8b 05 7d 0b 20 00 	mov    0x200b7d(%rip),%rax        # 600ff8 <__gmon_start__>
  40047b:	48 85 c0             	test   %rax,%rax
  40047e:	74 05                	je     400485 <_init+0x15>
  400480:	e8 6b 00 00 00       	callq  4004f0 <.plt.got>
  400485:	48 83 c4 08          	add    $0x8,%rsp
  400489:	c3                   	retq   

Disassembly of section .plt:

0000000000400490 <.plt>:
  400490:	ff 35 72 0b 20 00    	pushq  0x200b72(%rip)        # 601008 <_GLOBAL_OFFSET_TABLE_+0x8>
  400496:	ff 25 74 0b 20 00    	jmpq   *0x200b74(%rip)        # 601010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40049c:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004004a0 <puts@plt>:
  4004a0:	ff 25 72 0b 20 00    	jmpq   *0x200b72(%rip)        # 601018 <puts@GLIBC_2.2.5>
  4004a6:	68 00 00 00 00       	pushq  $0x0
  4004ab:	e9 e0 ff ff ff       	jmpq   400490 <.plt>

00000000004004b0 <printf@plt>:
  4004b0:	ff 25 6a 0b 20 00    	jmpq   *0x200b6a(%rip)        # 601020 <printf@GLIBC_2.2.5>
  4004b6:	68 01 00 00 00       	pushq  $0x1
  4004bb:	e9 d0 ff ff ff       	jmpq   400490 <.plt>

00000000004004c0 <gettimeofday@plt>:
  4004c0:	ff 25 62 0b 20 00    	jmpq   *0x200b62(%rip)        # 601028 <gettimeofday@GLIBC_2.2.5>
  4004c6:	68 02 00 00 00       	pushq  $0x2
  4004cb:	e9 c0 ff ff ff       	jmpq   400490 <.plt>

00000000004004d0 <__libc_start_main@plt>:
  4004d0:	ff 25 5a 0b 20 00    	jmpq   *0x200b5a(%rip)        # 601030 <__libc_start_main@GLIBC_2.2.5>
  4004d6:	68 03 00 00 00       	pushq  $0x3
  4004db:	e9 b0 ff ff ff       	jmpq   400490 <.plt>

00000000004004e0 <exit@plt>:
  4004e0:	ff 25 52 0b 20 00    	jmpq   *0x200b52(%rip)        # 601038 <exit@GLIBC_2.2.5>
  4004e6:	68 04 00 00 00       	pushq  $0x4
  4004eb:	e9 a0 ff ff ff       	jmpq   400490 <.plt>

Disassembly of section .plt.got:

00000000004004f0 <.plt.got>:
  4004f0:	ff 25 02 0b 20 00    	jmpq   *0x200b02(%rip)        # 600ff8 <__gmon_start__>
  4004f6:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

0000000000400500 <main>:
  check(x);
  return 0;
}

int main()
{
  400500:	48 83 ec 08          	sub    $0x8,%rsp
  // printf("LEN: %u, NTIMES: %lu\n\n", LEN, NTIMES);
  printf("                     Time    TPI\n");
  400504:	bf 68 09 40 00       	mov    $0x400968,%edi
  400509:	e8 92 ff ff ff       	callq  4004a0 <puts@plt>
  printf("              Loop    ns     ps/el     Checksum \n");
  40050e:	bf 90 09 40 00       	mov    $0x400990,%edi
  400513:	e8 88 ff ff ff       	callq  4004a0 <puts@plt>
  scale_shift();
  400518:	31 c0                	xor    %eax,%eax
  40051a:	e8 c1 01 00 00       	callq  4006e0 <scale_shift>
  // ss_intr_SSE();
  // ss_intr_AVX();
  exit(0);
  40051f:	31 ff                	xor    %edi,%edi
  400521:	e8 ba ff ff ff       	callq  4004e0 <exit@plt>

0000000000400526 <_start>:
  400526:	31 ed                	xor    %ebp,%ebp
  400528:	49 89 d1             	mov    %rdx,%r9
  40052b:	5e                   	pop    %rsi
  40052c:	48 89 e2             	mov    %rsp,%rdx
  40052f:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  400533:	50                   	push   %rax
  400534:	54                   	push   %rsp
  400535:	49 c7 c0 10 09 40 00 	mov    $0x400910,%r8
  40053c:	48 c7 c1 a0 08 40 00 	mov    $0x4008a0,%rcx
  400543:	48 c7 c7 00 05 40 00 	mov    $0x400500,%rdi
  40054a:	e8 81 ff ff ff       	callq  4004d0 <__libc_start_main@plt>
  40054f:	f4                   	hlt    

0000000000400550 <deregister_tm_clones>:
  400550:	b8 50 10 60 00       	mov    $0x601050,%eax
  400555:	48 3d 50 10 60 00    	cmp    $0x601050,%rax
  40055b:	74 13                	je     400570 <deregister_tm_clones+0x20>
  40055d:	b8 00 00 00 00       	mov    $0x0,%eax
  400562:	48 85 c0             	test   %rax,%rax
  400565:	74 09                	je     400570 <deregister_tm_clones+0x20>
  400567:	bf 50 10 60 00       	mov    $0x601050,%edi
  40056c:	ff e0                	jmpq   *%rax
  40056e:	66 90                	xchg   %ax,%ax
  400570:	c3                   	retq   
  400571:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400576:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40057d:	00 00 00 

0000000000400580 <register_tm_clones>:
  400580:	be 50 10 60 00       	mov    $0x601050,%esi
  400585:	48 81 ee 50 10 60 00 	sub    $0x601050,%rsi
  40058c:	48 89 f0             	mov    %rsi,%rax
  40058f:	48 c1 ee 3f          	shr    $0x3f,%rsi
  400593:	48 c1 f8 03          	sar    $0x3,%rax
  400597:	48 01 c6             	add    %rax,%rsi
  40059a:	48 d1 fe             	sar    %rsi
  40059d:	74 11                	je     4005b0 <register_tm_clones+0x30>
  40059f:	b8 00 00 00 00       	mov    $0x0,%eax
  4005a4:	48 85 c0             	test   %rax,%rax
  4005a7:	74 07                	je     4005b0 <register_tm_clones+0x30>
  4005a9:	bf 50 10 60 00       	mov    $0x601050,%edi
  4005ae:	ff e0                	jmpq   *%rax
  4005b0:	c3                   	retq   
  4005b1:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4005b6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4005bd:	00 00 00 

00000000004005c0 <__do_global_dtors_aux>:
  4005c0:	80 3d b9 0a 20 00 00 	cmpb   $0x0,0x200ab9(%rip)        # 601080 <completed.7338>
  4005c7:	75 17                	jne    4005e0 <__do_global_dtors_aux+0x20>
  4005c9:	55                   	push   %rbp
  4005ca:	48 89 e5             	mov    %rsp,%rbp
  4005cd:	e8 7e ff ff ff       	callq  400550 <deregister_tm_clones>
  4005d2:	5d                   	pop    %rbp
  4005d3:	c6 05 a6 0a 20 00 01 	movb   $0x1,0x200aa6(%rip)        # 601080 <completed.7338>
  4005da:	c3                   	retq   
  4005db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4005e0:	c3                   	retq   
  4005e1:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4005e6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4005ed:	00 00 00 

00000000004005f0 <frame_dummy>:
  4005f0:	eb 8e                	jmp    400580 <register_tm_clones>

00000000004005f2 <dummy>:
  4005f2:	55                   	push   %rbp
  4005f3:	48 89 e5             	mov    %rsp,%rbp
  4005f6:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  4005fa:	f3 0f 11 45 f4       	movss  %xmm0,-0xc(%rbp)
  4005ff:	f3 0f 11 4d f0       	movss  %xmm1,-0x10(%rbp)
  400604:	b8 00 00 00 00       	mov    $0x0,%eax
  400609:	5d                   	pop    %rbp
  40060a:	c3                   	retq   
  40060b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000400610 <get_wall_time>:
{
  400610:	48 83 ec 18          	sub    $0x18,%rsp
    if (gettimeofday(&time,NULL)) {
  400614:	31 f6                	xor    %esi,%esi
  400616:	48 89 e7             	mov    %rsp,%rdi
  400619:	e8 a2 fe ff ff       	callq  4004c0 <gettimeofday@plt>
  40061e:	85 c0                	test   %eax,%eax
  400620:	75 22                	jne    400644 <get_wall_time+0x34>
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
  400622:	c5 e8 57 d2          	vxorps %xmm2,%xmm2,%xmm2
  400626:	c4 e1 eb 2a 44 24 08 	vcvtsi2sdq 0x8(%rsp),%xmm2,%xmm0
  40062d:	c5 fb 59 0d 93 03 00 	vmulsd 0x393(%rip),%xmm0,%xmm1        # 4009c8 <_IO_stdin_used+0xa8>
  400634:	00 
  400635:	c4 e1 eb 2a 04 24    	vcvtsi2sdq (%rsp),%xmm2,%xmm0
}
  40063b:	48 83 c4 18          	add    $0x18,%rsp
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
  40063f:	c5 f3 58 c0          	vaddsd %xmm0,%xmm1,%xmm0
}
  400643:	c3                   	retq   
        exit(-1); // return 0;
  400644:	83 cf ff             	or     $0xffffffff,%edi
  400647:	e8 94 fe ff ff       	callq  4004e0 <exit@plt>
  40064c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000400650 <check>:
    for (unsigned int i = 0; i < LEN; i++)
  400650:	48 8d 87 00 10 00 00 	lea    0x1000(%rdi),%rax
    real sum = 0;
  400657:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
  40065b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
        sum += arr[i];
  400660:	c5 fa 58 07          	vaddss (%rdi),%xmm0,%xmm0
    for (unsigned int i = 0; i < LEN; i++)
  400664:	48 83 c7 04          	add    $0x4,%rdi
  400668:	48 39 f8             	cmp    %rdi,%rax
  40066b:	75 f3                	jne    400660 <check+0x10>
    printf("%f \n", sum);
  40066d:	bf 24 09 40 00       	mov    $0x400924,%edi
  400672:	b8 01 00 00 00       	mov    $0x1,%eax
  400677:	c5 fa 5a c0          	vcvtss2sd %xmm0,%xmm0,%xmm0
  40067b:	e9 30 fe ff ff       	jmpq   4004b0 <printf@plt>

0000000000400680 <init>:
    for (int j = 0; j < LEN; j++)
  400680:	c5 fa 10 05 58 03 00 	vmovss 0x358(%rip),%xmm0        # 4009e0 <_IO_stdin_used+0xc0>
  400687:	00 
  400688:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  40068d:	0f 1f 00             	nopl   (%rax)
	    x[j] = 1.0;
  400690:	c5 fa 11 00          	vmovss %xmm0,(%rax)
    for (int j = 0; j < LEN; j++)
  400694:	48 83 c0 04          	add    $0x4,%rax
  400698:	48 3d c0 20 60 00    	cmp    $0x6020c0,%rax
  40069e:	75 f0                	jne    400690 <init+0x10>
}
  4006a0:	31 c0                	xor    %eax,%eax
  4006a2:	c3                   	retq   
  4006a3:	0f 1f 00             	nopl   (%rax)
  4006a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4006ad:	00 00 00 

00000000004006b0 <results>:
{
  4006b0:	48 89 fe             	mov    %rdi,%rsi
    printf("%18s  %5.1f    %5.1f     ",
  4006b3:	b8 02 00 00 00       	mov    $0x2,%eax
  4006b8:	bf 29 09 40 00       	mov    $0x400929,%edi
  4006bd:	c5 fb 5e 15 13 03 00 	vdivsd 0x313(%rip),%xmm0,%xmm2        # 4009d8 <_IO_stdin_used+0xb8>
  4006c4:	00 
  4006c5:	c5 fb 5e 0d 03 03 00 	vdivsd 0x303(%rip),%xmm0,%xmm1        # 4009d0 <_IO_stdin_used+0xb0>
  4006cc:	00 
  4006cd:	c5 f9 28 c2          	vmovapd %xmm2,%xmm0
  4006d1:	e9 da fd ff ff       	jmpq   4004b0 <printf@plt>
  4006d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4006dd:	00 00 00 

00000000004006e0 <scale_shift>:
{
  4006e0:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
  4006e5:	48 83 e4 e0          	and    $0xffffffffffffffe0,%rsp
    init();
  4006e9:	31 c0                	xor    %eax,%eax
{
  4006eb:	41 ff 72 f8          	pushq  -0x8(%r10)
  4006ef:	55                   	push   %rbp
  4006f0:	48 89 e5             	mov    %rsp,%rbp
  4006f3:	41 54                	push   %r12
    start_t = get_wall_time();
  4006f5:	41 bc 00 00 f0 00    	mov    $0xf00000,%r12d
{
  4006fb:	41 52                	push   %r10
  4006fd:	53                   	push   %rbx
  4006fe:	bb c0 20 60 00       	mov    $0x6020c0,%ebx
  400703:	48 83 ec 38          	sub    $0x38,%rsp
    init();
  400707:	e8 74 ff ff ff       	callq  400680 <init>
    start_t = get_wall_time();
  40070c:	31 c0                	xor    %eax,%eax
  40070e:	e8 fd fe ff ff       	callq  400610 <get_wall_time>
  400713:	c5 fc 28 1d e5 02 00 	vmovaps 0x2e5(%rip),%ymm3        # 400a00 <_IO_stdin_used+0xe0>
  40071a:	00 
  40071b:	c5 fc 28 15 fd 02 00 	vmovaps 0x2fd(%rip),%ymm2        # 400a20 <_IO_stdin_used+0x100>
  400722:	00 
  400723:	c5 fb 11 45 c8       	vmovsd %xmm0,-0x38(%rbp)
        for (unsigned int i = 0; i < LEN; i++)
  400728:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  40072d:	0f 1f 00             	nopl   (%rax)
            x[i] = alpha*x[i] + beta;
  400730:	c5 e4 59 00          	vmulps (%rax),%ymm3,%ymm0
  400734:	48 83 c0 20          	add    $0x20,%rax
  400738:	c5 fc 58 c2          	vaddps %ymm2,%ymm0,%ymm0
  40073c:	c5 fc 29 40 e0       	vmovaps %ymm0,-0x20(%rax)
        for (unsigned int i = 0; i < LEN; i++)
  400741:	48 39 c3             	cmp    %rax,%rbx
  400744:	75 ea                	jne    400730 <scale_shift+0x50>
        dummy(x, alpha, beta);
  400746:	c5 fa 10 0d 96 02 00 	vmovss 0x296(%rip),%xmm1        # 4009e4 <_IO_stdin_used+0xc4>
  40074d:	00 
  40074e:	c5 fa 10 05 92 02 00 	vmovss 0x292(%rip),%xmm0        # 4009e8 <_IO_stdin_used+0xc8>
  400755:	00 
  400756:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  40075b:	c5 f8 77             	vzeroupper 
  40075e:	e8 8f fe ff ff       	callq  4005f2 <dummy>
    for (unsigned int nl = 0; nl < NTIMES; nl++)
  400763:	41 83 ec 01          	sub    $0x1,%r12d
  400767:	c5 fc 28 1d 91 02 00 	vmovaps 0x291(%rip),%ymm3        # 400a00 <_IO_stdin_used+0xe0>
  40076e:	00 
  40076f:	c5 fc 28 15 a9 02 00 	vmovaps 0x2a9(%rip),%ymm2        # 400a20 <_IO_stdin_used+0x100>
  400776:	00 
  400777:	75 af                	jne    400728 <scale_shift+0x48>
    end_t = get_wall_time();
  400779:	31 c0                	xor    %eax,%eax
  40077b:	c5 f8 77             	vzeroupper 
  40077e:	e8 8d fe ff ff       	callq  400610 <get_wall_time>
    results(end_t - start_t, "scale_shift");
  400783:	c5 fb 5c 45 c8       	vsubsd -0x38(%rbp),%xmm0,%xmm0
  400788:	bf 43 09 40 00       	mov    $0x400943,%edi
  40078d:	e8 1e ff ff ff       	callq  4006b0 <results>
    check(x);
  400792:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  400797:	e8 b4 fe ff ff       	callq  400650 <check>
}
  40079c:	48 83 c4 38          	add    $0x38,%rsp
  4007a0:	31 c0                	xor    %eax,%eax
  4007a2:	5b                   	pop    %rbx
  4007a3:	41 5a                	pop    %r10
  4007a5:	41 5c                	pop    %r12
  4007a7:	5d                   	pop    %rbp
  4007a8:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
  4007ac:	c3                   	retq   
  4007ad:	0f 1f 00             	nopl   (%rax)

00000000004007b0 <ss_intr_SSE>:
{
  4007b0:	55                   	push   %rbp
    init();
  4007b1:	31 c0                	xor    %eax,%eax
    start_t = get_wall_time();
  4007b3:	bd 00 00 f0 00       	mov    $0xf00000,%ebp
{
  4007b8:	53                   	push   %rbx
  4007b9:	bb c0 20 60 00       	mov    $0x6020c0,%ebx
  4007be:	48 83 ec 18          	sub    $0x18,%rsp
    init();
  4007c2:	e8 b9 fe ff ff       	callq  400680 <init>
    start_t = get_wall_time();
  4007c7:	31 c0                	xor    %eax,%eax
  4007c9:	e8 42 fe ff ff       	callq  400610 <get_wall_time>
  4007ce:	c5 f8 28 1d 6a 02 00 	vmovaps 0x26a(%rip),%xmm3        # 400a40 <_IO_stdin_used+0x120>
  4007d5:	00 
  4007d6:	c5 f8 28 15 72 02 00 	vmovaps 0x272(%rip),%xmm2        # 400a50 <_IO_stdin_used+0x130>
  4007dd:	00 
  4007de:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
        for (unsigned int i = 0; i < LEN; i+= SSE_LEN)
  4007e4:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  4007e9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
}

extern __inline __m128 __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_mul_ps (__m128 __A, __m128 __B)
{
  return (__m128) ((__v4sf)__A * (__v4sf)__B);
  4007f0:	c5 e0 59 00          	vmulps (%rax),%xmm3,%xmm0
  4007f4:	48 83 c0 10          	add    $0x10,%rax
  return (__m128) ((__v4sf)__A + (__v4sf)__B);
  4007f8:	c5 f8 58 c2          	vaddps %xmm2,%xmm0,%xmm0

/* Store four SPFP values.  The address must be 16-byte aligned.  */
extern __inline void __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_store_ps (float *__P, __m128 __A)
{
  *(__m128 *)__P = __A;
  4007fc:	c5 f8 29 40 f0       	vmovaps %xmm0,-0x10(%rax)
  400801:	48 39 c3             	cmp    %rax,%rbx
  400804:	75 ea                	jne    4007f0 <ss_intr_SSE+0x40>
        dummy(x, alpha, beta);
  400806:	c5 fa 10 0d d6 01 00 	vmovss 0x1d6(%rip),%xmm1        # 4009e4 <_IO_stdin_used+0xc4>
  40080d:	00 
  40080e:	c5 fa 10 05 d2 01 00 	vmovss 0x1d2(%rip),%xmm0        # 4009e8 <_IO_stdin_used+0xc8>
  400815:	00 
  400816:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  40081b:	e8 d2 fd ff ff       	callq  4005f2 <dummy>
    for (unsigned int nl = 0; nl < NTIMES; nl++)
  400820:	83 ed 01             	sub    $0x1,%ebp
  400823:	c5 f8 28 15 25 02 00 	vmovaps 0x225(%rip),%xmm2        # 400a50 <_IO_stdin_used+0x130>
  40082a:	00 
  40082b:	c5 f8 28 1d 0d 02 00 	vmovaps 0x20d(%rip),%xmm3        # 400a40 <_IO_stdin_used+0x120>
  400832:	00 
  400833:	75 af                	jne    4007e4 <ss_intr_SSE+0x34>
  end_t = get_wall_time();
  400835:	31 c0                	xor    %eax,%eax
  400837:	e8 d4 fd ff ff       	callq  400610 <get_wall_time>
  results(end_t - start_t, "ss_intr_SSE");
  40083c:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  400842:	bf 4f 09 40 00       	mov    $0x40094f,%edi
  400847:	e8 64 fe ff ff       	callq  4006b0 <results>
  check(x);
  40084c:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  400851:	e8 fa fd ff ff       	callq  400650 <check>
}
  400856:	48 83 c4 18          	add    $0x18,%rsp
  40085a:	31 c0                	xor    %eax,%eax
  40085c:	5b                   	pop    %rbx
  40085d:	5d                   	pop    %rbp
  40085e:	c3                   	retq   
  40085f:	90                   	nop

0000000000400860 <ss_intr_AVX>:
{
  400860:	48 83 ec 18          	sub    $0x18,%rsp
  init();
  400864:	31 c0                	xor    %eax,%eax
  400866:	e8 15 fe ff ff       	callq  400680 <init>
  start_t = get_wall_time();
  40086b:	31 c0                	xor    %eax,%eax
  40086d:	e8 9e fd ff ff       	callq  400610 <get_wall_time>
  end_t = get_wall_time();
  400872:	31 c0                	xor    %eax,%eax
  start_t = get_wall_time();
  400874:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
  end_t = get_wall_time();
  40087a:	e8 91 fd ff ff       	callq  400610 <get_wall_time>
  results(end_t - start_t, "ss_intr_AVX");
  40087f:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  400885:	bf 5b 09 40 00       	mov    $0x40095b,%edi
  40088a:	e8 21 fe ff ff       	callq  4006b0 <results>
  check(x);
  40088f:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  400894:	e8 b7 fd ff ff       	callq  400650 <check>
}
  400899:	31 c0                	xor    %eax,%eax
  40089b:	48 83 c4 18          	add    $0x18,%rsp
  40089f:	c3                   	retq   

00000000004008a0 <__libc_csu_init>:
  4008a0:	41 57                	push   %r15
  4008a2:	41 89 ff             	mov    %edi,%r15d
  4008a5:	41 56                	push   %r14
  4008a7:	49 89 f6             	mov    %rsi,%r14
  4008aa:	41 55                	push   %r13
  4008ac:	49 89 d5             	mov    %rdx,%r13
  4008af:	41 54                	push   %r12
  4008b1:	4c 8d 25 50 05 20 00 	lea    0x200550(%rip),%r12        # 600e08 <__frame_dummy_init_array_entry>
  4008b8:	55                   	push   %rbp
  4008b9:	48 8d 2d 50 05 20 00 	lea    0x200550(%rip),%rbp        # 600e10 <__init_array_end>
  4008c0:	53                   	push   %rbx
  4008c1:	4c 29 e5             	sub    %r12,%rbp
  4008c4:	31 db                	xor    %ebx,%ebx
  4008c6:	48 c1 fd 03          	sar    $0x3,%rbp
  4008ca:	48 83 ec 08          	sub    $0x8,%rsp
  4008ce:	e8 9d fb ff ff       	callq  400470 <_init>
  4008d3:	48 85 ed             	test   %rbp,%rbp
  4008d6:	74 1e                	je     4008f6 <__libc_csu_init+0x56>
  4008d8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4008df:	00 
  4008e0:	4c 89 ea             	mov    %r13,%rdx
  4008e3:	4c 89 f6             	mov    %r14,%rsi
  4008e6:	44 89 ff             	mov    %r15d,%edi
  4008e9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4008ed:	48 83 c3 01          	add    $0x1,%rbx
  4008f1:	48 39 eb             	cmp    %rbp,%rbx
  4008f4:	75 ea                	jne    4008e0 <__libc_csu_init+0x40>
  4008f6:	48 83 c4 08          	add    $0x8,%rsp
  4008fa:	5b                   	pop    %rbx
  4008fb:	5d                   	pop    %rbp
  4008fc:	41 5c                	pop    %r12
  4008fe:	41 5d                	pop    %r13
  400900:	41 5e                	pop    %r14
  400902:	41 5f                	pop    %r15
  400904:	c3                   	retq   
  400905:	90                   	nop
  400906:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40090d:	00 00 00 

0000000000400910 <__libc_csu_fini>:
  400910:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400914 <_fini>:
  400914:	48 83 ec 08          	sub    $0x8,%rsp
  400918:	48 83 c4 08          	add    $0x8,%rsp
  40091c:	c3                   	retq   
