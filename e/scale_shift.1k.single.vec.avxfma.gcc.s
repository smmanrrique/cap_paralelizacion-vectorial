
scale_shift.1k.single.vec.avxfma.gcc:     file format elf64-x86-64


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
  40051a:	e8 e1 01 00 00       	callq  400700 <scale_shift>
  // ss_intr_SSE();
  // ss_intr_AVX();
  exit(0);
  40051f:	31 ff                	xor    %edi,%edi
  400521:	e8 ba ff ff ff       	callq  4004e0 <exit@plt>
  400526:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40052d:	00 00 00 

0000000000400530 <set_fast_math>:
  400530:	0f ae 5c 24 fc       	stmxcsr -0x4(%rsp)
  400535:	81 4c 24 fc 40 80 00 	orl    $0x8040,-0x4(%rsp)
  40053c:	00 
  40053d:	0f ae 54 24 fc       	ldmxcsr -0x4(%rsp)
  400542:	c3                   	retq   

0000000000400543 <_start>:
  400543:	31 ed                	xor    %ebp,%ebp
  400545:	49 89 d1             	mov    %rdx,%r9
  400548:	5e                   	pop    %rsi
  400549:	48 89 e2             	mov    %rsp,%rdx
  40054c:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  400550:	50                   	push   %rax
  400551:	54                   	push   %rsp
  400552:	49 c7 c0 30 09 40 00 	mov    $0x400930,%r8
  400559:	48 c7 c1 c0 08 40 00 	mov    $0x4008c0,%rcx
  400560:	48 c7 c7 00 05 40 00 	mov    $0x400500,%rdi
  400567:	e8 64 ff ff ff       	callq  4004d0 <__libc_start_main@plt>
  40056c:	f4                   	hlt    
  40056d:	0f 1f 00             	nopl   (%rax)

0000000000400570 <deregister_tm_clones>:
  400570:	b8 50 10 60 00       	mov    $0x601050,%eax
  400575:	48 3d 50 10 60 00    	cmp    $0x601050,%rax
  40057b:	74 13                	je     400590 <deregister_tm_clones+0x20>
  40057d:	b8 00 00 00 00       	mov    $0x0,%eax
  400582:	48 85 c0             	test   %rax,%rax
  400585:	74 09                	je     400590 <deregister_tm_clones+0x20>
  400587:	bf 50 10 60 00       	mov    $0x601050,%edi
  40058c:	ff e0                	jmpq   *%rax
  40058e:	66 90                	xchg   %ax,%ax
  400590:	c3                   	retq   
  400591:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400596:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40059d:	00 00 00 

00000000004005a0 <register_tm_clones>:
  4005a0:	be 50 10 60 00       	mov    $0x601050,%esi
  4005a5:	48 81 ee 50 10 60 00 	sub    $0x601050,%rsi
  4005ac:	48 89 f0             	mov    %rsi,%rax
  4005af:	48 c1 ee 3f          	shr    $0x3f,%rsi
  4005b3:	48 c1 f8 03          	sar    $0x3,%rax
  4005b7:	48 01 c6             	add    %rax,%rsi
  4005ba:	48 d1 fe             	sar    %rsi
  4005bd:	74 11                	je     4005d0 <register_tm_clones+0x30>
  4005bf:	b8 00 00 00 00       	mov    $0x0,%eax
  4005c4:	48 85 c0             	test   %rax,%rax
  4005c7:	74 07                	je     4005d0 <register_tm_clones+0x30>
  4005c9:	bf 50 10 60 00       	mov    $0x601050,%edi
  4005ce:	ff e0                	jmpq   *%rax
  4005d0:	c3                   	retq   
  4005d1:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  4005d6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4005dd:	00 00 00 

00000000004005e0 <__do_global_dtors_aux>:
  4005e0:	80 3d 99 0a 20 00 00 	cmpb   $0x0,0x200a99(%rip)        # 601080 <completed.7338>
  4005e7:	75 17                	jne    400600 <__do_global_dtors_aux+0x20>
  4005e9:	55                   	push   %rbp
  4005ea:	48 89 e5             	mov    %rsp,%rbp
  4005ed:	e8 7e ff ff ff       	callq  400570 <deregister_tm_clones>
  4005f2:	5d                   	pop    %rbp
  4005f3:	c6 05 86 0a 20 00 01 	movb   $0x1,0x200a86(%rip)        # 601080 <completed.7338>
  4005fa:	c3                   	retq   
  4005fb:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400600:	c3                   	retq   
  400601:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  400606:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40060d:	00 00 00 

0000000000400610 <frame_dummy>:
  400610:	eb 8e                	jmp    4005a0 <register_tm_clones>

0000000000400612 <dummy>:
  400612:	55                   	push   %rbp
  400613:	48 89 e5             	mov    %rsp,%rbp
  400616:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  40061a:	f3 0f 11 45 f4       	movss  %xmm0,-0xc(%rbp)
  40061f:	f3 0f 11 4d f0       	movss  %xmm1,-0x10(%rbp)
  400624:	b8 00 00 00 00       	mov    $0x0,%eax
  400629:	5d                   	pop    %rbp
  40062a:	c3                   	retq   
  40062b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

0000000000400630 <get_wall_time>:
{
  400630:	48 83 ec 18          	sub    $0x18,%rsp
    if (gettimeofday(&time,NULL)) {
  400634:	31 f6                	xor    %esi,%esi
  400636:	48 89 e7             	mov    %rsp,%rdi
  400639:	e8 82 fe ff ff       	callq  4004c0 <gettimeofday@plt>
  40063e:	85 c0                	test   %eax,%eax
  400640:	75 1f                	jne    400661 <get_wall_time+0x31>
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
  400642:	c5 f0 57 c9          	vxorps %xmm1,%xmm1,%xmm1
  400646:	c4 e1 f3 2a 44 24 08 	vcvtsi2sdq 0x8(%rsp),%xmm1,%xmm0
  40064d:	c4 e1 f3 2a 0c 24    	vcvtsi2sdq (%rsp),%xmm1,%xmm1
  400653:	c4 e2 f1 99 05 8c 03 	vfmadd132sd 0x38c(%rip),%xmm1,%xmm0        # 4009e8 <_IO_stdin_used+0xa8>
  40065a:	00 00 
}
  40065c:	48 83 c4 18          	add    $0x18,%rsp
  400660:	c3                   	retq   
        exit(-1); // return 0;
  400661:	83 cf ff             	or     $0xffffffff,%edi
  400664:	e8 77 fe ff ff       	callq  4004e0 <exit@plt>
  400669:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)

0000000000400670 <check>:
    for (unsigned int i = 0; i < LEN; i++)
  400670:	48 8d 87 00 10 00 00 	lea    0x1000(%rdi),%rax
    real sum = 0;
  400677:	c5 f8 57 c0          	vxorps %xmm0,%xmm0,%xmm0
  40067b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
        sum += arr[i];
  400680:	c5 fa 58 07          	vaddss (%rdi),%xmm0,%xmm0
    for (unsigned int i = 0; i < LEN; i++)
  400684:	48 83 c7 04          	add    $0x4,%rdi
  400688:	48 39 f8             	cmp    %rdi,%rax
  40068b:	75 f3                	jne    400680 <check+0x10>
    printf("%f \n", sum);
  40068d:	bf 44 09 40 00       	mov    $0x400944,%edi
  400692:	b8 01 00 00 00       	mov    $0x1,%eax
  400697:	c5 fa 5a c0          	vcvtss2sd %xmm0,%xmm0,%xmm0
  40069b:	e9 10 fe ff ff       	jmpq   4004b0 <printf@plt>

00000000004006a0 <init>:
    for (int j = 0; j < LEN; j++)
  4006a0:	c5 fa 10 05 58 03 00 	vmovss 0x358(%rip),%xmm0        # 400a00 <_IO_stdin_used+0xc0>
  4006a7:	00 
  4006a8:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  4006ad:	0f 1f 00             	nopl   (%rax)
	    x[j] = 1.0;
  4006b0:	c5 fa 11 00          	vmovss %xmm0,(%rax)
    for (int j = 0; j < LEN; j++)
  4006b4:	48 83 c0 04          	add    $0x4,%rax
  4006b8:	48 3d c0 20 60 00    	cmp    $0x6020c0,%rax
  4006be:	75 f0                	jne    4006b0 <init+0x10>
}
  4006c0:	31 c0                	xor    %eax,%eax
  4006c2:	c3                   	retq   
  4006c3:	0f 1f 00             	nopl   (%rax)
  4006c6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4006cd:	00 00 00 

00000000004006d0 <results>:
    printf("%18s  %5.1f    %5.1f     ",
  4006d0:	c5 fb 59 15 20 03 00 	vmulsd 0x320(%rip),%xmm0,%xmm2        # 4009f8 <_IO_stdin_used+0xb8>
  4006d7:	00 
{
  4006d8:	48 89 fe             	mov    %rdi,%rsi
    printf("%18s  %5.1f    %5.1f     ",
  4006db:	b8 02 00 00 00       	mov    $0x2,%eax
  4006e0:	bf 49 09 40 00       	mov    $0x400949,%edi
  4006e5:	c5 fb 59 0d 03 03 00 	vmulsd 0x303(%rip),%xmm0,%xmm1        # 4009f0 <_IO_stdin_used+0xb0>
  4006ec:	00 
  4006ed:	c5 f9 28 c2          	vmovapd %xmm2,%xmm0
  4006f1:	e9 ba fd ff ff       	jmpq   4004b0 <printf@plt>
  4006f6:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4006fd:	00 00 00 

0000000000400700 <scale_shift>:
{
  400700:	4c 8d 54 24 08       	lea    0x8(%rsp),%r10
  400705:	48 83 e4 e0          	and    $0xffffffffffffffe0,%rsp
    init();
  400709:	31 c0                	xor    %eax,%eax
{
  40070b:	41 ff 72 f8          	pushq  -0x8(%r10)
  40070f:	55                   	push   %rbp
  400710:	48 89 e5             	mov    %rsp,%rbp
  400713:	41 54                	push   %r12
    start_t = get_wall_time();
  400715:	41 bc 00 00 f0 00    	mov    $0xf00000,%r12d
{
  40071b:	41 52                	push   %r10
  40071d:	53                   	push   %rbx
  40071e:	bb c0 20 60 00       	mov    $0x6020c0,%ebx
  400723:	48 83 ec 38          	sub    $0x38,%rsp
    init();
  400727:	e8 74 ff ff ff       	callq  4006a0 <init>
    start_t = get_wall_time();
  40072c:	31 c0                	xor    %eax,%eax
  40072e:	e8 fd fe ff ff       	callq  400630 <get_wall_time>
  400733:	c5 fc 28 1d e5 02 00 	vmovaps 0x2e5(%rip),%ymm3        # 400a20 <_IO_stdin_used+0xe0>
  40073a:	00 
  40073b:	c5 fc 28 15 fd 02 00 	vmovaps 0x2fd(%rip),%ymm2        # 400a40 <_IO_stdin_used+0x100>
  400742:	00 
  400743:	c5 fb 11 45 c8       	vmovsd %xmm0,-0x38(%rbp)
        for (unsigned int i = 0; i < LEN; i++)
  400748:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  40074d:	0f 1f 00             	nopl   (%rax)
            x[i] = alpha*x[i] + beta;
  400750:	c5 fc 28 c3          	vmovaps %ymm3,%ymm0
  400754:	c4 e2 6d 98 00       	vfmadd132ps (%rax),%ymm2,%ymm0
  400759:	48 83 c0 20          	add    $0x20,%rax
  40075d:	c5 fc 29 40 e0       	vmovaps %ymm0,-0x20(%rax)
        for (unsigned int i = 0; i < LEN; i++)
  400762:	48 39 c3             	cmp    %rax,%rbx
  400765:	75 e9                	jne    400750 <scale_shift+0x50>
        dummy(x, alpha, beta);
  400767:	c5 fa 10 0d 95 02 00 	vmovss 0x295(%rip),%xmm1        # 400a04 <_IO_stdin_used+0xc4>
  40076e:	00 
  40076f:	c5 fa 10 05 91 02 00 	vmovss 0x291(%rip),%xmm0        # 400a08 <_IO_stdin_used+0xc8>
  400776:	00 
  400777:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  40077c:	c5 f8 77             	vzeroupper 
  40077f:	e8 8e fe ff ff       	callq  400612 <dummy>
    for (unsigned int nl = 0; nl < NTIMES; nl++)
  400784:	41 83 ec 01          	sub    $0x1,%r12d
  400788:	c5 fc 28 1d 90 02 00 	vmovaps 0x290(%rip),%ymm3        # 400a20 <_IO_stdin_used+0xe0>
  40078f:	00 
  400790:	c5 fc 28 15 a8 02 00 	vmovaps 0x2a8(%rip),%ymm2        # 400a40 <_IO_stdin_used+0x100>
  400797:	00 
  400798:	75 ae                	jne    400748 <scale_shift+0x48>
    end_t = get_wall_time();
  40079a:	31 c0                	xor    %eax,%eax
  40079c:	c5 f8 77             	vzeroupper 
  40079f:	e8 8c fe ff ff       	callq  400630 <get_wall_time>
    results(end_t - start_t, "scale_shift");
  4007a4:	c5 fb 5c 45 c8       	vsubsd -0x38(%rbp),%xmm0,%xmm0
  4007a9:	bf 63 09 40 00       	mov    $0x400963,%edi
  4007ae:	e8 1d ff ff ff       	callq  4006d0 <results>
    check(x);
  4007b3:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  4007b8:	e8 b3 fe ff ff       	callq  400670 <check>
}
  4007bd:	48 83 c4 38          	add    $0x38,%rsp
  4007c1:	31 c0                	xor    %eax,%eax
  4007c3:	5b                   	pop    %rbx
  4007c4:	41 5a                	pop    %r10
  4007c6:	41 5c                	pop    %r12
  4007c8:	5d                   	pop    %rbp
  4007c9:	49 8d 62 f8          	lea    -0x8(%r10),%rsp
  4007cd:	c3                   	retq   
  4007ce:	66 90                	xchg   %ax,%ax

00000000004007d0 <ss_intr_SSE>:
{
  4007d0:	55                   	push   %rbp
    init();
  4007d1:	31 c0                	xor    %eax,%eax
    start_t = get_wall_time();
  4007d3:	bd 00 00 f0 00       	mov    $0xf00000,%ebp
{
  4007d8:	53                   	push   %rbx
  4007d9:	bb c0 20 60 00       	mov    $0x6020c0,%ebx
  4007de:	48 83 ec 18          	sub    $0x18,%rsp
    init();
  4007e2:	e8 b9 fe ff ff       	callq  4006a0 <init>
    start_t = get_wall_time();
  4007e7:	31 c0                	xor    %eax,%eax
  4007e9:	e8 42 fe ff ff       	callq  400630 <get_wall_time>
  4007ee:	c5 f8 28 1d 6a 02 00 	vmovaps 0x26a(%rip),%xmm3        # 400a60 <_IO_stdin_used+0x120>
  4007f5:	00 
  4007f6:	c5 f8 28 15 72 02 00 	vmovaps 0x272(%rip),%xmm2        # 400a70 <_IO_stdin_used+0x130>
  4007fd:	00 
  4007fe:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
        for (unsigned int i = 0; i < LEN; i+= SSE_LEN)
  400804:	b8 c0 10 60 00       	mov    $0x6010c0,%eax
  400809:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
/* Perform the respective operation on the four SPFP values in A and B.  */

extern __inline __m128 __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_add_ps (__m128 __A, __m128 __B)
{
  return (__m128) ((__v4sf)__A + (__v4sf)__B);
  400810:	c5 f8 28 c3          	vmovaps %xmm3,%xmm0
  400814:	c4 e2 69 98 00       	vfmadd132ps (%rax),%xmm2,%xmm0

/* Store four SPFP values.  The address must be 16-byte aligned.  */
extern __inline void __attribute__((__gnu_inline__, __always_inline__, __artificial__))
_mm_store_ps (float *__P, __m128 __A)
{
  *(__m128 *)__P = __A;
  400819:	48 83 c0 10          	add    $0x10,%rax
  40081d:	c5 f8 29 40 f0       	vmovaps %xmm0,-0x10(%rax)
  400822:	48 39 c3             	cmp    %rax,%rbx
  400825:	75 e9                	jne    400810 <ss_intr_SSE+0x40>
        dummy(x, alpha, beta);
  400827:	c5 fa 10 0d d5 01 00 	vmovss 0x1d5(%rip),%xmm1        # 400a04 <_IO_stdin_used+0xc4>
  40082e:	00 
  40082f:	c5 fa 10 05 d1 01 00 	vmovss 0x1d1(%rip),%xmm0        # 400a08 <_IO_stdin_used+0xc8>
  400836:	00 
  400837:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  40083c:	e8 d1 fd ff ff       	callq  400612 <dummy>
    for (unsigned int nl = 0; nl < NTIMES; nl++)
  400841:	83 ed 01             	sub    $0x1,%ebp
  400844:	c5 f8 28 15 24 02 00 	vmovaps 0x224(%rip),%xmm2        # 400a70 <_IO_stdin_used+0x130>
  40084b:	00 
  40084c:	c5 f8 28 1d 0c 02 00 	vmovaps 0x20c(%rip),%xmm3        # 400a60 <_IO_stdin_used+0x120>
  400853:	00 
  400854:	75 ae                	jne    400804 <ss_intr_SSE+0x34>
  end_t = get_wall_time();
  400856:	31 c0                	xor    %eax,%eax
  400858:	e8 d3 fd ff ff       	callq  400630 <get_wall_time>
  results(end_t - start_t, "ss_intr_SSE");
  40085d:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  400863:	bf 6f 09 40 00       	mov    $0x40096f,%edi
  400868:	e8 63 fe ff ff       	callq  4006d0 <results>
  check(x);
  40086d:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  400872:	e8 f9 fd ff ff       	callq  400670 <check>
}
  400877:	48 83 c4 18          	add    $0x18,%rsp
  40087b:	31 c0                	xor    %eax,%eax
  40087d:	5b                   	pop    %rbx
  40087e:	5d                   	pop    %rbp
  40087f:	c3                   	retq   

0000000000400880 <ss_intr_AVX>:
{
  400880:	48 83 ec 18          	sub    $0x18,%rsp
  init();
  400884:	31 c0                	xor    %eax,%eax
  400886:	e8 15 fe ff ff       	callq  4006a0 <init>
  start_t = get_wall_time();
  40088b:	31 c0                	xor    %eax,%eax
  40088d:	e8 9e fd ff ff       	callq  400630 <get_wall_time>
  end_t = get_wall_time();
  400892:	31 c0                	xor    %eax,%eax
  start_t = get_wall_time();
  400894:	c5 fb 11 44 24 08    	vmovsd %xmm0,0x8(%rsp)
  end_t = get_wall_time();
  40089a:	e8 91 fd ff ff       	callq  400630 <get_wall_time>
  results(end_t - start_t, "ss_intr_AVX");
  40089f:	c5 fb 5c 44 24 08    	vsubsd 0x8(%rsp),%xmm0,%xmm0
  4008a5:	bf 7b 09 40 00       	mov    $0x40097b,%edi
  4008aa:	e8 21 fe ff ff       	callq  4006d0 <results>
  check(x);
  4008af:	bf c0 10 60 00       	mov    $0x6010c0,%edi
  4008b4:	e8 b7 fd ff ff       	callq  400670 <check>
}
  4008b9:	31 c0                	xor    %eax,%eax
  4008bb:	48 83 c4 18          	add    $0x18,%rsp
  4008bf:	c3                   	retq   

00000000004008c0 <__libc_csu_init>:
  4008c0:	41 57                	push   %r15
  4008c2:	41 89 ff             	mov    %edi,%r15d
  4008c5:	41 56                	push   %r14
  4008c7:	49 89 f6             	mov    %rsi,%r14
  4008ca:	41 55                	push   %r13
  4008cc:	49 89 d5             	mov    %rdx,%r13
  4008cf:	41 54                	push   %r12
  4008d1:	4c 8d 25 28 05 20 00 	lea    0x200528(%rip),%r12        # 600e00 <__frame_dummy_init_array_entry>
  4008d8:	55                   	push   %rbp
  4008d9:	48 8d 2d 30 05 20 00 	lea    0x200530(%rip),%rbp        # 600e10 <__init_array_end>
  4008e0:	53                   	push   %rbx
  4008e1:	4c 29 e5             	sub    %r12,%rbp
  4008e4:	31 db                	xor    %ebx,%ebx
  4008e6:	48 c1 fd 03          	sar    $0x3,%rbp
  4008ea:	48 83 ec 08          	sub    $0x8,%rsp
  4008ee:	e8 7d fb ff ff       	callq  400470 <_init>
  4008f3:	48 85 ed             	test   %rbp,%rbp
  4008f6:	74 1e                	je     400916 <__libc_csu_init+0x56>
  4008f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  4008ff:	00 
  400900:	4c 89 ea             	mov    %r13,%rdx
  400903:	4c 89 f6             	mov    %r14,%rsi
  400906:	44 89 ff             	mov    %r15d,%edi
  400909:	41 ff 14 dc          	callq  *(%r12,%rbx,8)
  40090d:	48 83 c3 01          	add    $0x1,%rbx
  400911:	48 39 eb             	cmp    %rbp,%rbx
  400914:	75 ea                	jne    400900 <__libc_csu_init+0x40>
  400916:	48 83 c4 08          	add    $0x8,%rsp
  40091a:	5b                   	pop    %rbx
  40091b:	5d                   	pop    %rbp
  40091c:	41 5c                	pop    %r12
  40091e:	41 5d                	pop    %r13
  400920:	41 5e                	pop    %r14
  400922:	41 5f                	pop    %r15
  400924:	c3                   	retq   
  400925:	90                   	nop
  400926:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  40092d:	00 00 00 

0000000000400930 <__libc_csu_fini>:
  400930:	f3 c3                	repz retq 

Disassembly of section .fini:

0000000000400934 <_fini>:
  400934:	48 83 ec 08          	sub    $0x8,%rsp
  400938:	48 83 c4 08          	add    $0x8,%rsp
  40093c:	c3                   	retq   
