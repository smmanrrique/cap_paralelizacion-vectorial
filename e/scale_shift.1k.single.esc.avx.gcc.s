
scale_shift.1k.single.esc.avx.gcc:     file format elf64-x86-64


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
  400504:	bf b8 09 40 00       	mov    $0x4009b8,%edi
  400509:	e8 92 ff ff ff       	callq  4004a0 <puts@plt>
  printf("              Loop    ns     ps/el     Checksum \n");
  40050e:	bf e0 09 40 00       	mov    $0x4009e0,%edi
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
  400535:	49 c7 c0 60 09 40 00 	mov    $0x400960,%r8
  40053c:	48 c7 c1 f0 08 40 00 	mov    $0x4008f0,%rcx
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
  40062d:	c5 fb 59 0d e3 03 00 	vmulsd 0x3e3(%rip),%xmm0,%xmm1        # 400a18 <_IO_stdin_used+0xa8>
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
  40066d:	bf 74 09 40 00       	mov    $0x400974,%edi
  400672:	b8 01 00 00 00       	mov    $0x1,%eax
  400677:	c5 fa 5a c0          	vcvtss2sd %xmm0,%xmm0,%xmm0
  40067b:	e9 30 fe ff ff       	jmpq   4004b0 <printf@plt>

0000000000400680 <init>:
    for (int j = 0; j < LEN; j++)
  400680:	c5 fa 10 05 a8 03 00 	vmovss 0x3a8(%rip),%xmm0        # 400a30 <_IO_stdin_used+0xc0>
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
  4006b8:	bf 79 09 40 00       	mov    $0x400979,%edi
  4006bd:	c5 fb 5e 15 63 03 00 	vdivsd 0x363(%rip),%xmm0,%xmm2        # 400a28 <_IO_stdin_used+0xb8>
  4006c4:	00 
  4006c5:	c5 fb 5e 0d 53 03 00 	vdivsd 0x353(%rip),%xmm0,%xmm1        # 400a20 <_IO_stdin_used+0xb0>
  4006cc:	00 
  4006cd:	c5 f9 28 c2          	vmovapd %xmm2,%xmm0
  4006d1:	e9 da fd ff ff       	jmpq   4004b0 <printf@plt>
  4006d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4006dd:	00 00 00 

00000000004006e0 <scale_shift>:
{
  4006e0:	55                   	push   %rbp
    init();
  4006e1:	31 c0                	xor    %eax,%eax
    start_t = get_wall_time();
  4006e3:	bd 00 00 f0 00       	mov    $0xf00000,%ebp
{
  4006e8:	53                   	push   %rbx
  4006e9:	48 83 ec 18          	sub    $0x18,%rsp
    init();
  4006ed:	e8 8e ff ff ff       	callq  400680 <init>
    start_t = get_wall_time();
  4006f2:	31 c0                	xor    %eax,%eax
  4006f4:	e8 17 ff ff ff       	callq  400610 <get_wall_time>
  4006f9:	c5 fa 10 15 33 03 00 	vmovss 0x333(%rip),%xmm2        # 400a34 <_IO_stdin_used+0xc4>
  400700:	00 
  400701:	c5 fa 10 0d 2f 03 00 	vmovss 0x32f(%rip),%xmm1        # 400a38 <_IO_stdin_used+0xc8>
  400708:	00 
  400709:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
        for (unsigned int i = 0; i < LEN; i++)
  40070f:	bb c0 10 60 00       	mov    $0x6010c0,%ebx
{
  400714:	48 89 d8             	mov    %rbx,%rax
  400717:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  40071e:	00 00 
            x[i] = alpha*x[i] + beta;
  400720:	c5 ea 59 00          	vmulss (%rax),%xmm2,%xmm0
  400724:	48 83 c0 04          	add    $0x4,%rax
  400728:	c5 fa 58 c1          	vaddss %xmm1,%xmm0,%xmm0
  40072c:	c5 fa 11 40 fc       	vmovss %xmm0,-0x4(%rax)
        for (unsigned int i = 0; i < LEN; i++)
  400731:	48 3d c0 20 60 00    	cmp    $0x6020c0,%rax
  400737:	75 e7                	jne    400720 <scale_shift+0x40>
        dummy(x, alpha, beta);
  400739:	c5 f8 28 c2          	vmovaps %xmm2,%xmm0
  40073d:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  400742:	e8 ab fe ff ff       	callq  4005f2 <dummy>
    for (unsigned int nl = 0; nl < NTIMES; nl++)
  400747:	83 ed 01             	sub    $0x1,%ebp
  40074a:	c5 fa 10 15 e2 02 00 	vmovss 0x2e2(%rip),%xmm2        # 400a34 <_IO_stdin_used+0xc4>
  400751:	00 
  400752:	c5 fa 10 0d de 02 00 	vmovss 0x2de(%rip),%xmm1        # 400a38 <_IO_stdin_used+0xc8>
  400759:	00 
  40075a:	75 b3                	jne    40070f <scale_shift+0x2f>
    end_t = get_wall_time();
  40075c:	31 c0                	xor    %eax,%eax
  40075e:	e8 ad fe ff ff       	callq  400610 <get_wall_time>
    results(end_t - start_t, "scale_shift");
  400763:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  400769:	bf 93 09 40 00       	mov    $0x400993,%edi
  40076e:	e8 3d ff ff ff       	callq  4006b0 <results>
    real sum = 0;
  400773:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
        sum += arr[i];
  400777:	c5 fa 58 03          	vaddss (%rbx),%xmm0,%xmm0
    for (unsigned int i = 0; i < LEN; i++)
  40077b:	48 83 c3 04          	add    $0x4,%rbx
  40077f:	48 81 fb c0 20 60 00 	cmp    $0x6020c0,%rbx
  400786:	75 ef                	jne    400777 <scale_shift+0x97>
    printf("%f \n", sum);
  400788:	bf 74 09 40 00       	mov    $0x400974,%edi
  40078d:	b8 01 00 00 00       	mov    $0x1,%eax
  400792:	c5 fa 5a c0          	vcvtss2sd %xmm0,%xmm0,%xmm0
  400796:	e8 15 fd ff ff       	callq  4004b0 <printf@plt>
}
  40079b:	48 83 c4 18          	add    $0x18,%rsp
  40079f:	31 c0                	xor    %eax,%eax
  4007a1:	5b                   	pop    %rbx
  4007a2:	5d                   	pop    %rbp
  4007a3:	c3                   	retq   
  4007a4:	66 90                	xchg   %ax,%ax
  4007a6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4007ad:	00 00 00 

00000000004007b0 <ss_intr_SSE>:
{
  4007b0:	41 54                	push   %r12
    init();
  4007b2:	31 c0                	xor    %eax,%eax
    start_t = get_wall_time();
  4007b4:	41 bc 00 00 f0 00    	mov    $0xf00000,%r12d
{
  4007ba:	55                   	push   %rbp
  4007bb:	53                   	push   %rbx
  4007bc:	bb c0 20 60 00       	mov    $0x6020c0,%ebx
  4007c1:	48 83 ec 10          	sub    $0x10,%rsp
    init();
  4007c5:	e8 b6 fe ff ff       	callq  400680 <init>
    start_t = get_wall_time();
  4007ca:	31 c0                	xor    %eax,%eax
  4007cc:	e8 3f fe ff ff       	callq  400610 <get_wall_time>
  4007d1:	c5 f8 28 1d 67 02 00 	vmovaps 0x267(%rip),%xmm3        # 400a40 <_IO_stdin_used+0xd0>
  4007d8:	00 
  4007d9:	c5 f8 28 15 6f 02 00 	vmovaps 0x26f(%rip),%xmm2        # 400a50 <_IO_stdin_used+0xe0>
  4007e0:	00 
  4007e1:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
        for (unsigned int i = 0; i < LEN; i+= SSE_LEN)
  4007e7:	bd c0 10 60 00       	mov    $0x6010c0,%ebp
{
  4007ec:	48 89 e8             	mov    %rbp,%rax
  4007ef:	90                   	nop
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
        for (unsigned int i = 0; i < LEN; i+= SSE_LEN)
  400801:	48 39 c3             	cmp    %rax,%rbx
  400804:	75 ea                	jne    4007f0 <ss_intr_SSE+0x40>
        dummy(x, alpha, beta);
  400806:	c5 fa 10 0d 2a 02 00 	vmovss 0x22a(%rip),%xmm1        # 400a38 <_IO_stdin_used+0xc8>
  40080d:	00 
  40080e:	c5 fa 10 05 1e 02 00 	vmovss 0x21e(%rip),%xmm0        # 400a34 <_IO_stdin_used+0xc4>
  400815:	00 
  400816:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  40081b:	e8 d2 fd ff ff       	callq  4005f2 <dummy>
    for (unsigned int nl = 0; nl < NTIMES; nl++)
  400820:	41 83 ec 01          	sub    $0x1,%r12d
  400824:	c5 f8 28 1d 14 02 00 	vmovaps 0x214(%rip),%xmm3        # 400a40 <_IO_stdin_used+0xd0>
  40082b:	00 
  40082c:	c5 f8 28 15 1c 02 00 	vmovaps 0x21c(%rip),%xmm2        # 400a50 <_IO_stdin_used+0xe0>
  400833:	00 
  400834:	75 b1                	jne    4007e7 <ss_intr_SSE+0x37>
  end_t = get_wall_time();
  400836:	31 c0                	xor    %eax,%eax
  400838:	e8 d3 fd ff ff       	callq  400610 <get_wall_time>
  results(end_t - start_t, "ss_intr_SSE");
  40083d:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  400843:	bf 9f 09 40 00       	mov    $0x40099f,%edi
  400848:	e8 63 fe ff ff       	callq  4006b0 <results>
    real sum = 0;
  40084d:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
        sum += arr[i];
  400851:	c5 fa 58 45 00       	vaddss 0x0(%rbp),%xmm0,%xmm0
    for (unsigned int i = 0; i < LEN; i++)
  400856:	48 83 c5 04          	add    $0x4,%rbp
  40085a:	48 39 eb             	cmp    %rbp,%rbx
  40085d:	75 f2                	jne    400851 <ss_intr_SSE+0xa1>
    printf("%f \n", sum);
  40085f:	bf 74 09 40 00       	mov    $0x400974,%edi
  400864:	b8 01 00 00 00       	mov    $0x1,%eax
  400869:	c5 fa 5a c0          	vcvtss2sd %xmm0,%xmm0,%xmm0
  40086d:	e8 3e fc ff ff       	callq  4004b0 <printf@plt>
}
  400872:	48 83 c4 10          	add    $0x10,%rsp
  400876:	31 c0                	xor    %eax,%eax
  400878:	5b                   	pop    %rbx
  400879:	5d                   	pop    %rbp
  40087a:	41 5c                	pop    %r12
  40087c:	c3                   	retq   
  40087d:	0f 1f 00             	nopl   (%rax)

0000000000400880 <ss_intr_AVX>:
{
  400880:	48 83 ec 18          	sub    $0x18,%rsp
  init();
  400884:	31 c0                	xor    %eax,%eax
  400886:	e8 f5 fd ff ff       	callq  400680 <init>
  start_t = get_wall_time();
  40088b:	31 c0                	xor    %eax,%eax
  40088d:	e8 7e fd ff ff       	callq  400610 <get_wall_time>
  end_t = get_wall_time();
  400892:	31 c0                	xor    %eax,%eax
  start_t = get_wall_time();
  400894:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
  end_t = get_wall_time();
  40089a:	e8 71 fd ff ff       	callq  400610 <get_wall_time>
  results(end_t - start_t, "ss_intr_AVX");
  40089f:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  4008a5:	bf ab 09 40 00       	mov    $0x4009ab,%edi
  4008aa:	e8 01 fe ff ff       	callq  4006b0 <results>
    for (unsigned int i = 0; i < LEN; i++)
  4008af:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  4008b4:	ba c0 20 60 00       	mov    $0x6020c0,%edx
    real sum = 0;
  4008b9:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
  4008bd:	0f 1f 00             	nopl   (%rax)
        sum += arr[i];
  4008c0:	c5 fa 58 00          	vaddss (%rax),%xmm0,%xmm0
    for (unsigned int i = 0; i < LEN; i++)
  4008c4:	48 83 c0 04          	add    $0x4,%rax
  4008c8:	48 39 c2             	cmp    %rax,%rdx
  4008cb:	75 f3                	jne    4008c0 <ss_intr_AVX+0x40>
    printf("%f \n", sum);
  4008cd:	bf 74 09 40 00       	mov    $0x400974,%edi
  4008d2:	b8 01 00 00 00       	mov    $0x1,%eax
  4008d7:	c5 fa 5a c0          	vcvtss2sd %xmm0,%xmm0,%xmm0
  4008db:	e8 d0 fb ff ff       	callq  4004b0 <printf@plt>
}
  4008e0:	31 c0                	xor    %eax,%eax
  4008e2:	48 83 c4 18          	add    $0x18,%rsp
  4008e6:	c3                   	retq   
  4008e7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  4008ee:	00 00 

00000000004008f0 <__libc_csu_init>:
  4008f0:	41 57                	push   %r15
  4008f2:	41 89 ff             	mov    %edi,%r15d
  4008f5:	41 56                	push   %r14
  4008f7:	49 89 f6             	mov    %rsi,%r14
  4008fa:	41 55                	push   %r13
  4008fc:	49 89 d5             	mov    %rdx,%r13
  4008ff:	41 54                	push   %r12
  400901:	4c 8d 25 00 05 20 00 	lea    0x200500(%rip),%r12        # 600e08 <__frame_dummy_init_array_entry>
  400908:	55                   	push   %rbp
  400909:	48 8d 2d 00 05 20 00 	lea    0x200500(%rip),%rbp        # 600e10 <__init_array_end>
  400910:	53                   	push   %rbx
  400911:	4c 29 e5             	sub    %r12,%rbp
  400914:	31 db                	xor    %ebx,%ebx
  400916:	48 c1 fd 03          	sar    $0x3,%rbp
  40091a:	48 83 ec 08          	sub    $0x8,%rsp
  40091e:	e8 4d fb ff ff       	callq  400470 <_init>
  400923:	48 85 ed             	test   %rbp,%rbp
  400926:	74 1e                	je     400946 <__libc_csu_init+0x56>
  400928:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40092f:	00 
  400930:	4c 89 ea             	mov    %r13,%rdx
  400933:	4c 89 f6             	mov    %r14,%rsi
  400936:	44 89 ff             	mov    %r15d,%edi
  400939:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  40093d:	48 83 c3 01          	add    $0x1,%rbx
  400941:	48 39 eb             	cmp    %rbp,%rbx
  400944:	75 ea                	jne    400930 <__libc_csu_init+0x40>
  400946:	48 83 c4 08          	add    $0x8,%rsp
  40094a:	5b                   	pop    %rbx
  40094b:	5d                   	pop    %rbp
  40094c:	41 5c                	pop    %r12
  40094e:	41 5d                	pop    %r13
  400950:	41 5e                	pop    %r14
  400952:	41 5f                	pop    %r15
  400954:	c3                   	retq   
  400955:	90                   	nop
  400956:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40095d:	00 00 00 

0000000000400960 <__libc_csu_fini>:
  400960:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400964 <_fini>:
  400964:	48 83 ec 08          	sub    $0x8,%rsp
  400968:	48 83 c4 08          	add    $0x8,%rsp
  40096c:	c3                   	retq   
