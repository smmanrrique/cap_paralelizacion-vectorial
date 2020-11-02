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

## Notas generales

El trabajo puede presentarse de forma individual o en grupos de máximo dos personas.
Podéis trabajar en grupos mayores, pero **cada grupo debe elaborar el material a entregar de forma independiente**.
Hacedme llegar vuestros trabajos **en formato pdf** a través de la entrega habilitada en la web de la asignatura (moodle).
Incluid vuestro NIP en el nombre del fichero (vector_NIP.pdf). El documento deberá contener 
en su cabecera el nombre y apellidos de los autores y tendrá una extensión máxima de 4 páginas.  
**Plazo límite de entrega: domingo 15 de noviembre, 23h59m59s.**


## Parte 1. Vectorización automática

4.  ¿Cuántas instrucciones se ejecutan en el bucle interno (esc.avx, vec.avx, vec.avxfma y vec.avx512)?

            for (int i = 0; i < LEN; i++)
                x[i] = alpha*x[i] + beta

    Calcula la reducción en el número de instrucciones respecto la versión esc.avx.

	|  versión   |   icount   | reducción(%) | reducción(factor) |
	|:----------:|:----------:|:------------:|:-----------------:|
	|  esc.avx   |    6144    |       0      |        1.0        |
	|  vec.avx   |            |              |                   |
	| vec.avxfma |            |              |                   |
	| vec.avx512 |            |              |                   |

    Indica muy brevemente cómo has calculado los anteriores valores.


6.  A partir de los tiempos de ejecución obtenidos [...],
    calcula las siguientes métricas para todas las versiones ejecutadas:

    - Aceleraciones (_speedups_) de las versiones vectoriales sobre sus escalares (vec.avx y vec.avxfma respecto esc.avx).
    - Rendimiento (R) en GFLOPS.
    - Rendimiento pico (R~pico~) teórico de un núcleo (_core_), en GFLOPS.
      Para las versiones escalares, considerar que las unidades funcionales trabajan en modo escalar.
      Considerar asimismo la capacidad FMA de las unidades funcionales solamente para las versiones compiladas con soporte FMA.
    - Velocidad de ejecución de instrucciones (V~I~), en Ginstrucciones por segundo (GIPS).

    Indica brevemente cómo has realizado los cálculos.

	|  versión   | tiempo(ns) |  speed-up |  R(GFLOPS)  |R~pico~(GFLOPS)| V~I~(GIPS) |
	|:----------:|:----------:|:---------:|:-----------:|:-------------:|:----------:|
	|  esc.avx   |            |    1.0    |             |               |            |
	|  vec.avx   |            |           |             |               |            |
	| vec.avxfma |            |           |             |               |            |

    Notas: GFLOPS = 10^9^ FLOPS. GIPS = 10^9^ IPS.

    ¿La velocidad de ejecución de instrucciones es un buen indicador de rendimiento?  

    
## Parte 2. Vectorización manual mediante intrínsecos

2.  Escribe una nueva versión del bucle, `ss_intr_AVX()`, vectorizando de forma
    manual con intrínsecos AVX.
    Lista el código correspondiente a la función `ss_intr_AVX()`.

    Analiza el fichero que contiene el ensamblador de dicha función y
    busca las instrucciones correspondientes al bucle en `ss_intr_AVX()`.  
    ¿Hay alguna diferencia con las instrucciones correspondientes al bucle en `scale_shift()` (versión vec.avx)?  
    ¿Hay diferencia en el rendimiento de las funciones `scale_shift()` (versión vec.avx) y `ss_intr_AVX()`?