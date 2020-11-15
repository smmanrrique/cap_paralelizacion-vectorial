% Evaluación de la práctica 1: Fundamentos de Vectorización en x86  
  62222 Computación de Altas Prestaciones  
  Máster Universitario en Ingeniería Informática
% Jesús Alastruey Benedé  
  Área Arquitectura y Tecnología de Computadores  
  Departamento de Informática e Ingeniería de Sistemas  
  Escuela de Ingeniería y Arquitectura  
  Universidad de Zaragoza
% 31-octubre-2020
 
 
## Resumen
 
Para la evaluación de la práctica 1 vais a resolver algunas cuestiones
correspondientes a los puntos 1.4, 1.6 y 2.2 del guión de prácticas.
Los tiempos y métricas deberán obtenerse para las máquinas de los laboratorios L0.04 o L1.02.
Sed concisos en las respuestas. Se valorarán las referencias utilizadas._
 
4.  ¿Cuántas instrucciones se ejecutan en el bucle interno (esc.avx, vec.avx, vec.avxfma y vec.avx512)?
 
            for (int i = 0; i < LEN; i++)
                x[i] = alpha*x[i] + beta
 
    Calcula la reducción en el número de instrucciones respecto a la versión esc.avx.
 
        |  versión   |   icount   | reducción(%) | reducción(factor) |
        |:----------:|:----------:|:------------:|:-----------------:|
        |  esc.avx   |    6144    |       0      |        1.0        |
        |  vec.avx   |    768     |     87.5     |       0.125      |
        | vec.avxfma |    768     |     87.5     |       0.125       |
        | vec.avx512 |    384     |     93.7     |       0.0625       |
 
 
    Para el cálculo del ICOUNT se usó la fórmula ICOUNT = N × LEN donde N es el número de instrucciones en el cuerpo del bucle(6) y LEN el número de iteraciones del bucle(1024 inicialmente) este último valor es muy importante dado que el número de iteraciones está determinado por la extensión del SIMD. Calculemos el valor del LEN para vec.avx512 como ejemplo: Sabemos que este procesador trabaja con 512b y se usa un tipo float de 32b para las operaciones. Por lo que al dividir 512/32 obtenemos que podemos operar con 16 elementos a la vez. Si dividimos el número de iteraciones entre elementos que podemos manejar por iteración( 16) queda la siguiente cuenta 1024/16 obteniendo como resultado un LEN igual a 64 veces. Ahora si reemplazamos los valores en la ecuación mencionada previamente obtenemos:
 
        vec.avx512: ICOUNT = N × LEN = 6 × 64 = 384
 
    Para el cálculo de la reducción se toma el mismo ejemplo de  vec.avx512: 
 
        vec.avx512:reduccion = valor_original - nuevo_valor = 6144 - 384 = 5760
 
        vec.avx512: reducción = reducción / valor_original = 5760/6144 = 0.9375
 
        vec.avx512: reducción(%) = reducción(factor) * 100 = 93,7%
 
    Para el cálculo de la reducción(factor):
 
        vec.avx512: reducción(factor) = 1 - 0.9375 = 0.0625 
 
6.  A partir de los tiempos de ejecución obtenidos [...],
    
    calcula las siguientes métricas para todas las versiones ejecutadas:
 
  - Aceleraciones (_speedups_) de las versiones vectoriales sobre sus escalares (vec.avx y vec.avxfma respecto esc.avxfma). Para el cálculo de speedup usaremos la siguiente fórmula con un cálculo de ejemplo:
 
          vec.avxfma: Speedup = tiempo_scalar/tiempo_vectorial = 465.9/70.5 = 6.60
 
  - Rendimiento (R) en GFLOPS.
 
    Para el cálculo de GFLOPS necesitaremos calcular los FLOPS(Operaciones de punto flotante por segundo.Validamos en el código del bucle interno cuántas operaciones de punto flotante se ejecutan, se obtienen un total de 2 operaciones punto flotante(1 sumas y 1 multiplicación) por lo que el cálculo total de operaciones punto flotante vendrá determinado por 2*1024 para el caso escalar que es igual a 2048. Como el tiempo que se obtiene en la ejecución viene dado en nanosegundos se multiplica por 10^-6 para determinar el número de instrucciones en segundos.
 
          FLOPS = instruccion_flotantes/segundo = 2048/(465.9 * 10^-9) = 4395793088.645 op/seg
 
    Una vez que calculamos los FLOPS la fórmula a usar para el cálculo de GLOPS seria:
 
          GFLOPS = FLOPS/10^9 = 4395793.088 / 10^9 = 4.395 Billones de operaciones flotantes por segundo
 
  - Rendimiento pico (R~pico~) teórico de un núcleo (_core_), en GFLOPS.
 
    Para el cálculo de R~pico se ejecutó el siguiente comando para ver las características de la computadora del laboratorio donde se ejecutó la práctica
 
          >lscpu
 
      Con este comando podemos readirmar que el modelo del procesador con el que se esta trabajando es este caso intel core i5-4570 de 3.2 G.H , con el nombre del procesador buscamos en la [pagina wikichip](https://en.wikichip.org/wiki/intel/core_i5/i5-4570r) la informacion de  las unidades funcionales de coma flotante y la anchura vectorial de las UFs.
 
 
      Para las versiones escalares, considerar que las unidades funcionales trabajan en modo escalar.
      Considerar asimismo la capacidad FMA de las unidades funcionales solamente para las versiones compiladas con soporte FMA. En este caso se calculará el Rpico para el vec.avx: 
 
        Rpico = 3.2 GHz x 2 UF x 8 FLOP/ciclo = 51.2 GFLOPS
 
  - Velocidad de ejecución de instrucciones (V~I~), en Ginstrucciones por segundo (GIPS).
    
    Para los cálculos de GIPS es necesario calcular IPS(Instrucciones por segundo) lo procederemos a calcular para el caso escalar que posee 6144 instrucciones entre el tiempo de ejecución como este viene dado en nanosegundos se multiplica por 10^-6 para determinar el número de instrucciones en segundos.
 
          IPS = instrucción/segundo = 6144/(465.9*10^-9) =  13187379265.93 inst/seg
 
      Una vez que calculamos los IPS la fórmula a usar para el cálculo de GIPS seria:
 
          GIPS = IPS/10^9 = 13.18 Billones de instrucciones por segundo
 
    |  versión   | tiempo(ns) |  speed-up |  R(GFLOPS)  |R~pico~(GFLOPS)| V~I~(GIPS) |
    |:----------:|:----------:|:---------:|:-----------:|:-------------:|:----------:|
    |  esc.avx   |   465.9    |    1.0    |  4.39   |     6.4           |   13.18   |
    |  vec.avx   |   80.1     |    5.81   |  25.56  |     51.2          |   9.58    |
    | vec.avxfma |   70.5     |    6.60   |  29.04  |      51.2         |   10.89   |
 
  ¿La velocidad de ejecución de instrucciones es un buen indicador de rendimiento?  
  
  Actualmente existen varias métricas de rendimiento la usada con mayor frecuencia es el tiempo de ejecución. Usamos esto para evaluar si una arquitectura es óptima o tiene mejor rendimiento respecto a a otra.Se debe tomar en cuenta que esta no es la única medida, también se podrían usar MIPS Y GFLOPS. El problema de usar MIPS es que dependiendo de la arquitectura del procesador(RISC, CISC) y su ISA(Instruction Set Arquitecture) el número de instrucciones de un fragmento de código estará condicionado por esto. Sin embargo con los GFLOPS o número de operaciones en punto flotante va hacer la misma sin importar la arquitectura por lo que diría que es más confiable.
 
 
## Parte 2. Vectorización manual mediante intrínsecos
 
2.  Escribe una nueva versión del bucle, `ss_intr_AVX()`, vectorizando de forma
    manual con intrínsecos AVX.
    Lista el código correspondiente a la función `ss_intr_AVX()`.
 
    Analiza el fichero que contiene el ensamblador de dicha función y
    busca las instrucciones correspondientes al bucle en `ss_intr_AVX()`.  
    ¿Hay alguna diferencia con las instrucciones correspondientes al bucle en `scale_shift()` (versión vec.avx)?  
    ¿Hay diferencia en el rendimiento de las funciones `scale_shift()` (versión vec.avx) y `ss_intr_AVX()`?