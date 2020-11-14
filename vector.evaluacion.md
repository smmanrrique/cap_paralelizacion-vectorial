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

_Para la evaluación de la práctica 1 vais a resolver algunas cuestiones
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

    Para el calculo de la reducción(factor):

        vec.avx512: reducción(factor) = 1 - 0.9375 = 0.0625 

6.  A partir de los tiempos de ejecución obtenidos [...],
    
    calcula las siguientes métricas para todas las versiones ejecutadas:

  - Aceleraciones (_speedups_) de las versiones vectoriales sobre sus escalares (vec.avx y vec.avxfma respecto esc.avxfma). Para el calculo de speedup usaremos la siguiente formula con un calculo de ejemplo:

          vec.avxfma: Speedup = tiempo_scalar/tiempo_vectorial = 465.9/70.5 = 6.60

  - Rendimiento (R) en GFLOPS.

    Para el calculo de GFLOPS necesitaremos calcular los FLOPS(Operaciones de punto flotante por segundo.Validamos en el codigo del bucle interno cuantas operaciones de punto flotante se ejecutan, se obtienen un total de 2 operaciones punto flotante(1 sumas y 1 multiplicacion) por lo que el calculo total de operaciones punto flotante vendra determinado por 2*1024 para el caso escalar que es igual a 2048. Como el tiempo que se obtiene en la ejecucion viene dado en nanosegundos se multiplica por 10^-6 para determinar el numero de intrucciones en segundos.

          FLOPS = instruccion_flotantes/segundo = 2048/(465.9 * 10^-9) = 4395793088.645 op/seg

    Una vez que calculamos los FLOPS la formula a usar para el calculo de GLOPS seria:

          GFLOPS = FLOPS/10^9 = 4395793.088 / 10^9 = 4.395 Billones de operaciones flotantes por segundo

  - Rendimiento pico (R~pico~) teórico de un núcleo (_core_), en GFLOPS.

      Para las versiones escalares, considerar que las unidades funcionales trabajan en modo escalar.
      Considerar asimismo la capacidad FMA de las unidades funcionales solamente para las versiones compiladas con soporte FMA.

    Os envío información que puede servir de ayuda para el cálculo del Rendimiento pico (Rpico) teórico de un núcleo (core), en GFLOPS.

    El rendimiento pico es la máxima velocidad teórica a la que el procesador puede ejecutar operaciones de punto flotante (FLOPs/tiempo).
    Para obtenerlo hay que asumir un caso extremo: que todas las instrucciones que lanza el procesador son operaciones de punto flotante.
    El rendimiento pico depende de la frecuencia del procesador, la cantidad de unidades funcionales (UF) y su latencia de iniciación (issue latency).
    Por ejemplo, si un procesador cuya frecuencia es 1.5 GHz tiene 2 UFs que puede hacer una operación cada ciclo (UF escalar), entonces:

        Rpico = 1.5 GHz x 2 UF x 1 FLOP/ciclo = 3 GFLOPS
        
    Las operaciones suma y multiplicación de números reales tienen una latencia de iniciación de 1 ciclo, es decir, las unidades funcionales que realizan estas operaciones pueden ejecutar una operación cada ciclo.
    En el caso de las instrucciones vectoriales, recordad que las UFs pueden iniciar N operaciones en un ciclo.
    Por tanto, para el procesador en el que se han realizado los experimentos, hay que buscar su frecuencia, número de UFs de coma flotante y la anchura vectorial de las UFs.


  - Velocidad de ejecución de instrucciones (V~I~), en Ginstrucciones por segundo (GIPS).
    
    Para los calculos de GIPS es necesario calcular IPS(Intrucciones por segundo) lo procederemos a calcular para el caso escalar que posee 6144 intrucciones entre el tiempo de ejecucion como este viene dado en nanosegundos se multiplica por 10^-6 para determinar el numero de intrucciones en segundos.

          IPS = instruccion/segundo = 6144/(465.9*10^-9) =  13187379265.93 inst/seg

      Una vez que calculamos los IPS la formula a usar para el calculo de GIPS seria:

          GIPS = IPS/10^9 = 13.18 Billones de intrucciones por segundo

    |  versión   | tiempo(ns) |  speed-up |  R(GFLOPS)  |R~pico~(GFLOPS)| V~I~(GIPS) |
    |:----------:|:----------:|:---------:|:-----------:|:-------------:|:----------:|
    |  esc.avx   |   465.9    |    1.0    |  4.39  |               |   13.18   |
    |  vec.avx   |   80.1     |    5.81   |  25.56  |               |   9.58   |
    | vec.avxfma |   70.5     |    6.60   |  29.04  |               |   10.89   |

  ¿La velocidad de ejecución de instrucciones es un buen indicador de rendimiento?  
  
  Actualmente existen varias metricas de rendimiento la usada con mayor frecuencia es el tiempo de ejecución. Usamos este para evaluar si una arquitectura es optima o tiene mejor rendimiento respecto a a otra.Se debe tomar en cuenta que esta no es la unica medidas tamien se podrian usar MIPS Y GFLOPS. El problema de usar MIPS es que dependiendo de la arquitectura del procesador(RISC, CISC) y su ISA(Instruction Set Arquitecture) el numero de intrucciones de un fragmento de codigo estara condicionado por esto. Sin embargo con los GFLOPS o numero de operaciones en punto flotante va hacer la misma sin importar la arquitectura por lo que diria que es mas confiable.


## Parte 2. Vectorización manual mediante intrínsecos

2.  Escribe una nueva versión del bucle, `ss_intr_AVX()`, vectorizando de forma
    manual con intrínsecos AVX.
    Lista el código correspondiente a la función `ss_intr_AVX()`.

    Analiza el fichero que contiene el ensamblador de dicha función y
    busca las instrucciones correspondientes al bucle en `ss_intr_AVX()`.  
    ¿Hay alguna diferencia con las instrucciones correspondientes al bucle en `scale_shift()` (versión vec.avx)?  
    ¿Hay diferencia en el rendimiento de las funciones `scale_shift()` (versión vec.avx) y `ss_intr_AVX()`?