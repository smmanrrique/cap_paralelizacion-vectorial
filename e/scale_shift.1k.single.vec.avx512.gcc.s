
scale_shift.1k.single.vec.avx512.gcc:     file format elf64-x86-64


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
  400504:	bf 88 09 40 00       	mov    $0x400988,%edi
  400509:	e8 92 ff ff ff       	callq  4004a0 <puts@plt>
  printf("              Loop    ns     ps/el     Checksum \n");
  40050e:	bf b0 09 40 00       	mov    $0x4009b0,%edi
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
  400535:	49 c7 c0 20 09 40 00 	mov    $0x400920,%r8
  40053c:	48 c7 c1 b0 08 40 00 	mov    $0x4008b0,%rcx
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
  40062d:	c5 fb 59 0d b3 03 00 	vmulsd 0x3b3(%rip),%xmm0,%xmm1        # 4009e8 <_IO_stdin_used+0xa8>
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
  40066d:	bf 44 09 40 00       	mov    $0x400944,%edi
  400672:	b8 01 00 00 00       	mov    $0x1,%eax
  400677:	c5 fa 5a c0          	vcvtss2sd %xmm0,%xmm0,%xmm0
  40067b:	e9 30 fe ff ff       	jmpq   4004b0 <printf@plt>

0000000000400680 <init>:
    for (int j = 0; j < LEN; j++)
  400680:	c5 fa 10 05 78 03 00 	vmovss 0x378(%rip),%xmm0        # 400a00 <_IO_stdin_used+0xc0>
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
  4006b8:	bf 49 09 40 00       	mov    $0x400949,%edi
  4006bd:	c5 fb 5e 15 33 03 00 	vdivsd 0x333(%rip),%xmm0,%xmm2        # 4009f8 <_IO_stdin_used+0xb8>
  4006c4:	00 
  4006c5:	c5 fb 5e 0d 23 03 00 	vdivsd 0x323(%rip),%xmm0,%xmm1        # 4009f0 <_IO_stdin_used+0xb0>
  4006cc:	00 
  4006cd:	c5 f9 28 c2          	vmovapd %xmm2,%xmm0
  4006d1:	e9 da fd ff ff       	jmpq   4004b0 <printf@plt>
  4006d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4006dd:	00 00 00 

00000000004006e0 <scale_shift>:
{
  4006e0:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
  4006e5:	48 83 e4 c0          	and    $0xffffffffffffffc0,%rsp
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
  400703:	48 83 ec 58          	sub    $0x58,%rsp
    init();
  400707:	e8 74 ff ff ff       	callq  400680 <init>
    start_t = get_wall_time();
  40070c:	31 c0                	xor    %eax,%eax
  40070e:	e8 fd fe ff ff       	callq  400610 <get_wall_time>
  400713:	62 f1 7c 48 28 1d 23 	vmovaps 0x323(%rip),%zmm3        # 400a40 <_IO_stdin_used+0x100>
  40071a:	03 00 00 
  40071d:	62 f1 7c 48 28 15 59 	vmovaps 0x359(%rip),%zmm2        # 400a80 <_IO_stdin_used+0x140>
  400724:	03 00 00 
  400727:	c5 fb 11 45 c8       	vmovsd %xmm0,-0x38(%rbp)
        for (unsigned int i = 0; i < LEN; i++)
  40072c:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  400731:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
            x[i] = alpha*x[i] + beta;
  400738:	62 f1 64 48 59 00    	vmulps (%rax),%zmm3,%zmm0
  40073e:	48 83 c0 40          	add    $0x40,%rax
  400742:	62 f1 7c 48 58 c2    	vaddps %zmm2,%zmm0,%zmm0
  400748:	62 f1 7c 48 29 40 ff 	vmovaps %zmm0,-0x40(%rax)
        for (unsigned int i = 0; i < LEN; i++)
  40074f:	48 39 c3             	cmp    %rax,%rbx
  400752:	75 e4                	jne    400738 <scale_shift+0x58>
        dummy(x, alpha, beta);
  400754:	c5 fa 10 0d a8 02 00 	vmovss 0x2a8(%rip),%xmm1        # 400a04 <_IO_stdin_used+0xc4>
  40075b:	00 
  40075c:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  400761:	c5 fa 10 05 9f 02 00 	vmovss 0x29f(%rip),%xmm0        # 400a08 <_IO_stdin_used+0xc8>
  400768:	00 
  400769:	c5 f8 77             	vzeroupper 
  40076c:	e8 81 fe ff ff       	callq  4005f2 <dummy>
    for (unsigned int nl = 0; nl < NTIMES; nl++)
  400771:	41 83 ec 01          	sub    $0x1,%r12d
  400775:	62 f1 7c 48 28 1d c1 	vmovaps 0x2c1(%rip),%zmm3        # 400a40 <_IO_stdin_used+0x100>
  40077c:	02 00 00 
  40077f:	62 f1 7c 48 28 15 f7 	vmovaps 0x2f7(%rip),%zmm2        # 400a80 <_IO_stdin_used+0x140>
  400786:	02 00 00 
  400789:	75 a1                	jne    40072c <scale_shift+0x4c>
    end_t = get_wall_time();
  40078b:	31 c0                	xor    %eax,%eax
  40078d:	c5 f8 77             	vzeroupper 
  400790:	e8 7b fe ff ff       	callq  400610 <get_wall_time>
    results(end_t - start_t, "scale_shift");
  400795:	c5 fb 5c 45 c8       	vsubsd -0x38(%rbp),%xmm0,%xmm0
  40079a:	bf 63 09 40 00       	mov    $0x400963,%edi
  40079f:	e8 0c ff ff ff       	callq  4006b0 <results>
    check(x);
  4007a4:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  4007a9:	e8 a2 fe ff ff       	callq  400650 <check>
}
  4007ae:	48 83 c4 58          	add    $0x58,%rsp
  4007b2:	31 c0                	xor    %eax,%eax
  4007b4:	5b                   	pop    %rbx
  4007b5:	41 5a                	pop    %r10
  4007b7:	41 5c                	pop    %r12
  4007b9:	5d                   	pop    %rbp
  4007ba:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
  4007be:	c3                   	retq   
  4007bf:	90                   	nop

00000000004007c0 <ss_intr_SSE>:
{
  4007c0:	55                   	push   %rbp
    init();
  4007c1:	31 c0                	xor    %eax,%eax
    start_t = get_wall_time();
  4007c3:	bd 00 00 f0 00       	mov    $0xf00000,%ebp
{
  4007c8:	53                   	push   %rbx
  4007c9:	bb c0 20 60 00       	mov    $0x6020c0,%ebx
  4007ce:	48 83 ec 18          	sub    $0x18,%rsp
    init();
  4007d2:	e8 a9 fe ff ff       	callq  400680 <init>
    start_t = get_wall_time();
  4007d7:	31 c0                	xor    %eax,%eax
  4007d9:	e8 32 fe ff ff       	callq  400610 <get_wall_time>
  4007de:	c5 f8 28 1d da 02 00 	vmovaps 0x2da(%rip),%xmm3        # 400ac0 <_IO_stdin_used+0x180>
  4007e5:	00 
  4007e6:	c5 f8 28 15 e2 02 00 	vmovaps 0x2e2(%rip),%xmm2        # 400ad0 <_IO_stdin_used+0x190>
  4007ed:	00 
  4007ee:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
        for (unsigned int i = 0; i < LEN; i+= SSE_LEN)
  4007f4:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  4007f9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
}

extern __inline __m128 __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_mul_ps (__m128 __A, __m128 __B)
{
  return (__m128) ((__v4sf)__A * (__v4sf)__B);
  400800:	c5 e0 59 00          	vmulps (%rax),%xmm3,%xmm0
  400804:	48 83 c0 10          	add    $0x10,%rax
  return (__m128) ((__v4sf)__A + (__v4sf)__B);
  400808:	c5 f8 58 c2          	vaddps %xmm2,%xmm0,%xmm0

/* Store four SPFP values.  The address must be 16-byte aligned.  */
extern __inline void __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_store_ps (float *__P, __m128 __A)
{
  *(__m128 *)__P = __A;
  40080c:	c5 f8 29 40 f0       	vmovaps %xmm0,-0x10(%rax)
  400811:	48 39 c3             	cmp    %rax,%rbx
  400814:	75 ea                	jne    400800 <ss_intr_SSE+0x40>
        dummy(x, alpha, beta);
  400816:	c5 fa 10 0d e6 01 00 	vmovss 0x1e6(%rip),%xmm1        # 400a04 <_IO_stdin_used+0xc4>
  40081d:	00 
  40081e:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  400823:	c5 fa 10 05 dd 01 00 	vmovss 0x1dd(%rip),%xmm0        # 400a08 <_IO_stdin_used+0xc8>
  40082a:	00 
  40082b:	e8 c2 fd ff ff       	callq  4005f2 <dummy>
    for (unsigned int nl = 0; nl < NTIMES; nl++)
  400830:	83 ed 01             	sub    $0x1,%ebp
  400833:	c5 f8 28 15 95 02 00 	vmovaps 0x295(%rip),%xmm2        # 400ad0 <_IO_stdin_used+0x190>
  40083a:	00 
  40083b:	c5 f8 28 1d 7d 02 00 	vmovaps 0x27d(%rip),%xmm3        # 400ac0 <_IO_stdin_used+0x180>
  400842:	00 
  400843:	75 af                	jne    4007f4 <ss_intr_SSE+0x34>
  end_t = get_wall_time();
  400845:	31 c0                	xor    %eax,%eax
  400847:	e8 c4 fd ff ff       	callq  400610 <get_wall_time>
  results(end_t - start_t, "ss_intr_SSE");
  40084c:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  400852:	bf 6f 09 40 00       	mov    $0x40096f,%edi
  400857:	e8 54 fe ff ff       	callq  4006b0 <results>
  check(x);
  40085c:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  400861:	e8 ea fd ff ff       	callq  400650 <check>
}
  400866:	48 83 c4 18          	add    $0x18,%rsp
  40086a:	31 c0                	xor    %eax,%eax
  40086c:	5b                   	pop    %rbx
  40086d:	5d                   	pop    %rbp
  40086e:	c3                   	retq   
  40086f:	90                   	nop

0000000000400870 <ss_intr_AVX>:
{
  400870:	48 83 ec 18          	sub    $0x18,%rsp
  init();
  400874:	31 c0                	xor    %eax,%eax
  400876:	e8 05 fe ff ff       	callq  400680 <init>
  start_t = get_wall_time();
  40087b:	31 c0                	xor    %eax,%eax
  40087d:	e8 8e fd ff ff       	callq  400610 <get_wall_time>
  end_t = get_wall_time();
  400882:	31 c0                	xor    %eax,%eax
  start_t = get_wall_time();
  400884:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
  end_t = get_wall_time();
  40088a:	e8 81 fd ff ff       	callq  400610 <get_wall_time>
  results(end_t - start_t, "ss_intr_AVX");
  40088f:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  400895:	bf 7b 09 40 00       	mov    $0x40097b,%edi
  40089a:	e8 11 fe ff ff       	callq  4006b0 <results>
  check(x);
  40089f:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  4008a4:	e8 a7 fd ff ff       	callq  400650 <check>
}
  4008a9:	31 c0                	xor    %eax,%eax
  4008ab:	48 83 c4 18          	add    $0x18,%rsp
  4008af:	c3                   	retq   

00000000004008b0 <__libc_csu_init>:
  4008b0:	41 57                	push   %r15
  4008b2:	41 89 ff             	mov    %edi,%r15d
  4008b5:	41 56                	push   %r14
  4008b7:	49 89 f6             	mov    %rsi,%r14
  4008ba:	41 55                	push   %r13
  4008bc:	49 89 d5             	mov    %rdx,%r13
  4008bf:	41 54                	push   %r12
  4008c1:	4c 8d 25 40 05 20 00 	lea    0x200540(%rip),%r12        # 600e08 <__frame_dummy_init_array_entry>
  4008c8:	55                   	push   %rbp
  4008c9:	48 8d 2d 40 05 20 00 	lea    0x200540(%rip),%rbp        # 600e10 <__init_array_end>
  4008d0:	53                   	push   %rbx
  4008d1:	4c 29 e5             	sub    %r12,%rbp
  4008d4:	31 db                	xor    %ebx,%ebx
  4008d6:	48 c1 fd 03          	sar    $0x3,%rbp
  4008da:	48 83 ec 08          	sub    $0x8,%rsp
  4008de:	e8 8d fb ff ff       	callq  400470 <_init>
  4008e3:	48 85 ed             	test   %rbp,%rbp
  4008e6:	74 1e                	je     400906 <__libc_csu_init+0x56>
  4008e8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4008ef:	00 
  4008f0:	4c 89 ea             	mov    %r13,%rdx
  4008f3:	4c 89 f6             	mov    %r14,%rsi
  4008f6:	44 89 ff             	mov    %r15d,%edi
  4008f9:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  4008fd:	48 83 c3 01          	add    $0x1,%rbx
  400901:	48 39 eb             	cmp    %rbp,%rbx
  400904:	75 ea                	jne    4008f0 <__libc_csu_init+0x40>
  400906:	48 83 c4 08          	add    $0x8,%rsp
  40090a:	5b                   	pop    %rbx
  40090b:	5d                   	pop    %rbp
  40090c:	41 5c                	pop    %r12
  40090e:	41 5d                	pop    %r13
  400910:	41 5e                	pop    %r14
  400912:	41 5f                	pop    %r15
  400914:	c3                   	retq   
  400915:	90                   	nop
  400916:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40091d:	00 00 00 

0000000000400920 <__libc_csu_fini>:
  400920:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400924 <_fini>:
  400924:	48 83 ec 08          	sub    $0x8,%rsp
  400928:	48 83 c4 08          	add    $0x8,%rsp
  40092c:	c3                   	retq   
