#set document(title: "Practica 3 - Mitm y suplantacion", author: "Adrian Garcia Mejias")
#set page(numbering: "1", margin: (x: 2.5cm, y: 2.5cm))
#set text(font: "New Computer Modern", size: 11pt, lang: "es")
#set heading(numbering: "1.1")
#set par(justify: true)

#align(center)[
  #v(2cm)
  #text(size: 20pt, weight: "bold")[Universidad Europea de Madrid]
  #v(0.3cm)
  #text(size: 16pt)[Laboratorio de Hacking]
  #v(1.5cm)
  #line(length: 60%)
  #v(0.5cm)
  #text(size: 22pt, weight: "bold")[Practica 3 - Mitm y suplantacion]
  #v(0.5cm)
  #line(length: 60%)
  #v(2cm)
  #text(size: 12pt)[
    *Autor/a:* Adrian Garcia Mejias \
    *Titulacion:* Grado en Ingenieria Informatica \
    *Asignatura:* Laboratorio de Hacking \
    *Fecha de entrega:* 26 de abril
  ]
  #v(1fr)
]

#pagebreak()

#heading(numbering: none)[Resumen]
<resumen>

Este trabajo estudia, en un pequeno laboratorio propio y aislado (nunca
contra sistemas reales de terceros), dos formas en las que alguien
podria "colarse" en medio de una conversacion entre dos ordenadores sin
que estos se den cuenta, y como detectar cuando esto esta ocurriendo.

La primera parte trata sobre como los dispositivos de una misma red
local se encuentran entre si. Cuando un ordenador quiere hablar con otro
de su misma red, pregunta en voz alta "quien tiene esta direccion" y
confia ciegamente en la primera respuesta que recibe. Esto permite que
alguien malintencionado responda antes que el dispositivo legitimo,
haciendose pasar por el, y consiguiendo que todo el trafico pase primero
por su ordenador antes de llegar a su destino real -- como si alguien
suplantara la identidad del cartero para leer el correo de otra persona
antes de entregarlo. Se ha construido un pequeno programa capaz de hacer
exactamente esto de forma controlada, y otro programa distinto capaz de
detectarlo: si una misma direccion "responde" desde dos identidades
distintas en poco tiempo, es una senal clara de que algo sospechoso esta
pasando.

La segunda parte trata sobre el sistema que traduce nombres de paginas
web (como "www.ejemplo.com") en las direcciones numericas que realmente
usan los ordenadores para comunicarse. Un atacante puede aprovechar este
sistema de dos formas: intentando "adivinar" respuestas falsas antes de
que llegue la respuesta real (para enganar al sistema y redirigir a los
usuarios a paginas falsas), o preguntando muy rapido por muchos nombres
inventados para averiguar que sistemas existen dentro de una empresa sin
que nadie se lo diga directamente. Se ha construido un sistema que
detecta este patron: si una misma direccion recibe demasiadas respuestas
de "ese nombre no existe" en muy poco tiempo, salta una alerta.

Los resultados muestran que ambas tecnicas de ataque, aunque tecnicamente
sencillas de llevar a cabo, dejan un rastro claro y detectable si se
vigila el trafico de red de la forma adecuada -- la clave no esta en
impedir que estos ataques existan (los protocolos afectados llevan
decadas en uso y son dificiles de cambiar), sino en saber reconocer sus
sintomas a tiempo.

#pagebreak()

#outline(title: "Indice", indent: auto)

#pagebreak()

= Introduccion
<introduccion>

Tras el reconocimiento pasivo (Practica 1) y el reconocimiento activo
(Practica 2), esta tercera practica aborda un tipo de tecnica distinto:
los ataques de *Man-In-The-Middle* (MITM) y suplantacion, centrados no en
descubrir informacion sino en *interceptar o manipular* la comunicacion
entre dos partes que confian mutuamente en la integridad de los
protocolos de red que utilizan.

Se abordan dos vectores concretos, ambos explotando debilidades
estructurales de protocolos sin autenticacion fuerte por diseno:

+ *ARP Spoofing*: el protocolo ARP (Address Resolution Protocol) no
  autentica sus respuestas, permitiendo a un atacante en la misma red
  local falsificar la asociacion IP-MAC de otros hosts y posicionarse
  como intermediario de su trafico.
+ *DNS Snooping y ataque de Kaminsky*: el protocolo DNS, en su forma
  clasica sin DNSSEC, tampoco autentica fuertemente sus respuestas mas
  alla de un identificador de transaccion facilmente adivinable en
  rafaga, permitiendo tanto el envenenamiento de cache (Kaminsky) como el
  mapeo de infraestructura interna mediante fuerza bruta de subdominios
  (DNS snooping).

El objetivo de esta practica no es unicamente ejecutar estos ataques,
sino sobre todo *implementar sistemas de deteccion basados en firmas*
capaces de identificarlos en tiempo real analizando el trafico de red,
un enfoque tipico de un IDS (Intrusion Detection System) de red.

Tal como exige expresamente el enunciado de la asignatura, toda actividad
de suplantacion y envenenamiento se ha limitado estrictamente a redes
virtuales propias, desplegadas mediante `docker-compose` en contenedores
aislados. En ningun momento se ha dirigido trafico de ataque hacia
resolutores DNS publicos, ni se ha interceptado trafico fuera del
entorno Docker configurado especificamente para esta practica.

Los objetivos concretos de esta practica son:

+ Definir un escenario de red en contenedores con una victima, un router
  y un servidor web en una red externa, y verificar su conectividad.
+ Investigar y utilizar `bettercap` para el envenenamiento de tablas
  ARP, documentando cualquier limitacion encontrada.
+ Implementar una funcion de deteccion (`alert_arpspoof`) que identifique
  anomalias en las respuestas ARP indicativas de envenenamiento.
+ Definir un segundo escenario de red con un resolver DNS y un servidor
  DNS autoritativo.
+ Implementar una funcion de deteccion (`alert_dnssnooping`) basada en
  umbral de volumen de respuestas NXDOMAIN.
+ Validar ambos sistemas de deteccion mediante scripts en scapy que
  generen el trafico de ataque correspondiente, evidenciando las alertas
  resultantes.

En ningun momento de esta practica se ha realizado ninguna actividad de
suplantacion o envenenamiento contra sistemas ajenos al laboratorio
Docker desplegado y controlado en su totalidad por el autor de este
informe.

= Desarrollo
<desarrollo>

== Deteccion de envenenamiento ARP
<arp-spoofing>

=== Topologia del laboratorio
<arp-topologia>

Se ha definido, mediante `docker-compose` @docker_compose_tool, un
escenario de red con tres contenedores en dos subredes distintas,
simulando una topologia realista donde el trafico entre una victima y un
servidor externo debe pasar obligatoriamente por un router intermedio:

- *Victima* (`192.168.10.20`): contenedor Alpine en la red interna
  `lan_interna` (`192.168.10.0/24`).
- *Router* (`192.168.10.2` / `192.168.20.2`): contenedor Alpine con
  reenvio IP activo (`sysctls: net.ipv4.ip_forward=1`), presente en ambas
  redes, actuando de puente entre la victima y el servidor.
- *Servidor web* (`192.168.20.10`): contenedor nginx en la red externa
  `lan_externa` (`192.168.20.0/24`).

Cada contenedor incorpora en su arranque la configuracion de rutas
necesaria (`ip route add`) para que el trafico victima <-> servidor
fluya correctamente a traves del router, verificado mediante una prueba
de conectividad extremo a extremo (`ping` con perdida de paquetes 0%)
antes de proceder con el ataque. Esta topologia situa al atacante (la
maquina Kali, conectada a la interfaz bridge de `lan_interna`) en la
misma capa de enlace que la victima y el router, condicion necesaria
para que un ataque de ARP spoofing sea posible, ya que el protocolo ARP
no se enruta mas alla de la red local.

=== Intento de uso de bettercap
<arp-bettercap>

Tal como exige el enunciado, se investigo y se intento utilizar
*bettercap* v2.41.5 @bettercap_tool para iniciar el envenenamiento de las
tablas ARP de la victima y el router. Tras multiples intentos —
incluyendo la generacion de trafico ICMP continuo para mantener los hosts
activos, la limpieza de la cache ARP de ambos extremos, y el ajuste del
periodo de refresco de descubrimiento de host (`net.recon.period`) — la
herramienta presento de forma reproducible el error `could not find spoof
targets`, incluso confirmando mediante `net.probe` que si detectaba
correctamente ambos objetivos (eventos `endpoint.new`), para perderlos
segundos despues (`endpoint.lost`) en un ciclo repetido que impedia al
modulo `arp.spoof` mantenerlos como objetivos validos.

Esta limitacion coincide con problemas reportados publicamente por otros
usuarios de bettercap en entornos de red virtualizados o en contenedores
(issues #1047, #979 y #942 del repositorio oficial del proyecto en
GitHub), sin una solucion definitiva documentada a la fecha de esta
practica. El registro completo de la investigacion y los comandos
probados se adjunta en `bettercap_troubleshooting.txt`, en esta misma
carpeta del repositorio.

=== Envenenamiento ARP manual con scapy
<arp-manual-scapy>

Dado que la limitacion identificada es de la propia herramienta y no del
diseno del laboratorio (la conectividad ya se habia verificado como
correcta), se opto por implementar el envenenamiento directamente con
*scapy* @scapy_tool, mediante el script `arp_spoof.py`. El script:

+ Resuelve las MAC reales de la victima y el router mediante una peticion
  ARP legitima (`srp` con broadcast).
+ Construye, para cada extremo, una trama Ethernet + ARP falsa (`op=2`,
  "is-at") que asocia la IP del otro extremo con la MAC del atacante, y
  la reenvia periodicamente (cada 2 segundos) para mantener el
  envenenamiento activo frente a la caducidad natural de las entradas
  ARP.
+ Al recibir una interrupcion (Ctrl+C), restaura las entradas ARP reales
  en ambos extremos, evitando dejar la red del laboratorio en un estado
  inconsistente.

Tras ejecutar el ataque, la inspeccion directa de las tablas ARP de
ambos contenedores confirma el envenenamiento: tanto la victima como el
router asocian la IP del otro extremo con la MAC del atacante
(`02:42:86:4c:b7:0b`) en lugar de su MAC real (ver @fig-arp-poisoned).

#figure(
  image("images/arp_tables_poisoned.png", width: 90%),
  caption: [Tablas ARP de la victima y el router tras el ataque, mostrando la MAC del atacante suplantando a ambos extremos.],
) <fig-arp-poisoned>

=== Deteccion con `alert_arpspoof`
<arp-deteccion>

Para detectar este tipo de ataque se ha implementado la funcion
`alert_arpspoof` (fichero `alert_arpspoof.py`), que monitoriza
pasivamente el trafico ARP de la interfaz del laboratorio mediante
`sniff()` de scapy. La firma de deteccion se basa en el indicador mas
fiable de ARP spoofing: *una misma direccion IP respondiendo (`is-at`,
`op=2`) desde mas de una direccion MAC dentro de una ventana temporal
reciente* (30 segundos en esta implementacion). En una red sana, cada IP
mantiene una unica MAC estable; la aparicion de una segunda MAC para la
misma IP es, con muy alta probabilidad, indicio de una respuesta ARP
falsificada.

Al ejecutar `alert_arpspoof.py` en paralelo al ataque manual descrito en
la seccion anterior, el detector genero alertas de forma inmediata y
consistente para ambas IPs afectadas (ver @fig-arp-detection),
confirmando tanto la eficacia del ataque como la correccion de la firma
de deteccion implementada. Antes de iniciar el ataque, el detector no
genero ninguna alerta, evidenciando ausencia de falsos positivos en
condiciones de trafico ARP normal.

#figure(
  image("images/arp_attack_and_detection.png", width: 90%),
  caption: [Alertas generadas por `alert_arpspoof.py` durante la ejecucion del ataque manual con scapy.],
) <fig-arp-detection>

== Suplantacion y anomalias DNS
<dns-snooping>

=== Contexto: el ataque de Kaminsky y el DNS snooping
<dns-contexto>

El *ataque de Kaminsky* (Dan Kaminsky, 2008) explota una debilidad
estructural del protocolo DNS clasico: al no autenticar sus respuestas
mas alla de un identificador de transaccion de 16 bits y un puerto de
origen, un atacante puede enviar una rafaga masiva de consultas hacia un
resolver por subdominios inexistentes de un dominio legitimo (por
ejemplo, `aleatorio1.banco.com`, `aleatorio2.banco.com`...), y
simultaneamente inundar al resolver con respuestas falsificadas que
intentan adivinar el identificador de transaccion correcto antes de que
llegue la respuesta real del servidor autoritativo. Si una respuesta
falsificada acierta, el resolver la almacena en cache como legitima,
envenenando su cache DNS para todos los clientes que lo consulten
posteriormente -- pudiendo redirigir trafico legitimo hacia
infraestructura del atacante.

El *DNS snooping* (o mapeo de subdominios) comparte el mismo patron de
trafico superficial -- rafagas de consultas a subdominios inexistentes
o poco comunes -- pero con un objetivo distinto: no busca envenenar la
cache, sino inferir la topologia interna de una organizacion observando
que subdominios existen (respuesta positiva) frente a los que no
(NXDOMAIN), o abusando de la cache compartida de un resolver para
determinar si un dominio ha sido consultado recientemente por otros
usuarios de la misma red.

Ambas tecnicas comparten una firma observable identica desde la
perspectiva de deteccion: *un volumen anormalmente alto de consultas a
subdominios inexistentes de un mismo dominio, en un periodo de tiempo
corto*, lo que justifica implementar una deteccion basada en umbral
sobre el volumen de respuestas NXDOMAIN, tal como exige el enunciado de
esta practica.

=== Escenario de red
<dns-topologia>

Se ha definido, mediante `docker-compose` @docker_compose_tool, un
segundo escenario con dos contenedores en la red `lan_dns`
(`192.168.30.0/24`): un *servidor DNS* (`192.168.30.10`) con una zona
propia (`lab.local`) y un *resolver DNS* (`192.168.30.20`) configurado
para reenviar consultas al servidor autoritativo. Ambos se han
desplegado con la imagen `cytopia/bind`, unica encontrada con soporte
multi-arquitectura (incluyendo ARM64) entre las probadas.

Durante la configuracion del reenvio explicito (`forward only`) del
resolver hacia el servidor autoritativo se encontro una limitacion del
entrypoint de la imagen, que regenera la configuracion desde variables
de entorno en cada arranque, dificultando persistir una opcion no
soportada nativamente por dichas variables. Se resolvio montando un
`named.conf` propio y autosuficiente, arrancando `named` directamente sin
pasar por el script de entrada de la imagen. Independientemente del
mecanismo interno de resolucion, el resolver cumple la funcion necesaria
para esta practica: responder de forma consistente con `NXDOMAIN` ante
consultas a subdominios inexistentes, que es precisamente el
comportamiento que la tecnica de Kaminsky/DNS snooping explota y que el
sistema de deteccion implementado debe identificar.

=== Deteccion con `alert_dnssnooping`
<dns-deteccion>

Se ha implementado la funcion `alert_dnssnooping` (fichero
`alert_dnssnooping.py`), que monitoriza pasivamente el trafico DNS de la
interfaz del laboratorio mediante `sniff()` de scapy @scapy_tool,
filtrando por puerto UDP 53. La firma de deteccion implementada es la
exigida por el enunciado: *deteccion por volumen (threshold) de
respuestas NXDOMAIN recibidas por una misma IP dentro de una ventana
temporal*. Concretamente, la funcion:

+ Analiza cada paquete DNS de respuesta (`qr=1`) con codigo de respuesta
  `rcode=3` (NXDOMAIN).
+ Mantiene, por IP destino de la respuesta, una lista de marcas de
  tiempo de respuestas NXDOMAIN recientes, descartando las que quedan
  fuera de la ventana configurada (por defecto, 10 segundos).
+ Si el numero de respuestas NXDOMAIN dentro de la ventana alcanza el
  umbral configurado (por defecto, 8), dispara una alerta y reinicia el
  contador de esa IP, evitando alertas repetidas por cada paquete
  adicional de la misma rafaga (gestion de falsos positivos por
  duplicacion de alertas).

Los umbrales (`--threshold` y `--window`) son configurables por linea de
comandos, permitiendo ajustar la sensibilidad del sistema segun el
volumen de trafico DNS legitimo esperado en la red monitorizada -- un
umbral demasiado bajo generaria falsos positivos con trafico normal
(errores tipograficos de usuarios, por ejemplo), mientras que uno
demasiado alto podria no detectar rafagas de ataque mas lentas y
sigilosas.

=== Validacion con generador de trafico en scapy
<dns-validacion>

Para validar el sistema se ha implementado `dns_snooping_attack.py`, un
script en scapy que genera una rafaga configurable de consultas DNS
hacia subdominios aleatorios (8 caracteres alfanumericos) de un dominio
base, simulando el patron de trafico caracteristico de Kaminsky/DNS
snooping. Al ejecutar una rafaga de 20 consultas contra el resolver del
laboratorio con `alert_dnssnooping.py` escuchando en paralelo (umbral: 8
NXDOMAIN / 10s), el sistema disparo multiples alertas de forma
consistente durante la ejecucion del ataque (ver @fig-dns-detection).

Cabe destacar que, al capturar en modo promiscuo sobre la interfaz
bridge compartida de Docker, el detector observa el trafico NXDOMAIN
asociado a varias IPs de la topologia (el resolver, el servidor, y la
propia maquina atacante), reflejo de como el trafico DNS de la rafaga
atraviesa multiples perspectivas de la red virtual del laboratorio. Este
comportamiento no afecta a la validez de la deteccion: en cualquiera de
las IPs monitorizadas, el volumen de NXDOMAIN generado por el ataque
supera claramente el umbral configurado, confirmando la eficacia de la
firma implementada.

#figure(
  image("images/dns_snooping_detection.png", width: 90%),
  caption: [Alertas generadas por `alert_dnssnooping.py` durante la ejecucion de la rafaga de consultas a subdominios aleatorios con `dns_snooping_attack.py`.],
) <fig-dns-detection>

= Resultados
<resultados>

A continuacion se resumen de forma tabulada los principales resultados
de la investigacion.

== ARP Spoofing

#figure(
  table(
    columns: (auto, auto, auto),
    align: left,
    table.header([*Host*], [*MAC real*], [*MAC tras el ataque*]),
    [Victima (192.168.10.20) -- entrada del router], [02:42:c0:a8:0a:02], [02:42:86:4c:b7:0b (atacante)],
    [Router (192.168.10.2) -- entrada de la victima], [02:42:c0:a8:0a:14], [02:42:86:4c:b7:0b (atacante)],
  ),
  caption: [Tablas ARP antes y despues del ataque manual con scapy @scapy_tool.],
)

#figure(
  table(
    columns: (auto, auto),
    align: left,
    table.header([*Metrica*], [*Valor*]),
    [Intervalo de reenvio del veneno], [2 segundos],
    [Ventana de deteccion (`alert_arpspoof`)], [30 segundos],
    [Alertas generadas durante el ataque], [Continuas, una por IP y ciclo de deteccion],
    [Falsos positivos antes del ataque], [0],
  ),
  caption: [Parametros y resultados del sistema de deteccion de ARP spoofing.],
)

== DNS Snooping / Kaminsky

#figure(
  table(
    columns: (auto, auto),
    align: left,
    table.header([*Parametro*], [*Valor*]),
    [Umbral de alerta (`--threshold`)], [8 respuestas NXDOMAIN],
    [Ventana temporal (`--window`)], [10 segundos],
    [Consultas enviadas en la rafaga de prueba], [20],
    [Longitud de subdominio aleatorio], [8 caracteres alfanumericos],
    [Dominio base], [lab.local],
  ),
  caption: [Configuracion empleada en la validacion del sistema de deteccion DNS snooping @scapy_tool.],
)

#figure(
  table(
    columns: (auto, auto, auto),
    align: left,
    table.header([*Codigo de respuesta DNS*], [*Significado*], [*Detectado como*]),
    [NXDOMAIN (rcode=3)], [Subdominio inexistente], [Contabilizado hacia el umbral],
    [NOERROR (rcode=0)], [Subdominio existente], [Ignorado por la firma (trafico legitimo)],
  ),
  caption: [Codigos de respuesta DNS relevantes para la firma de deteccion implementada.],
)



= Conclusiones
<conclusiones>

Esta practica ha demostrado, en un laboratorio controlado, dos vectores
de ataque que comparten una caracteristica de fondo: explotan protocolos
de red (ARP y DNS) disenados en una epoca en la que la autenticacion
fuerte de las respuestas no era una prioridad de diseno, confiando en su
lugar en la buena fe de los participantes de la red.

El envenenamiento ARP demostro ser trivial de ejecutar a nivel tecnico
-- construir y reenviar periodicamente respuestas ARP falsificadas es una
tarea de pocas lineas de codigo -- y, sin embargo, extremadamente
efectivo: en cuestion de segundos, tanto la victima como el router
quedaron completamente engañados, redirigiendo su trafico mutuo a traves
del atacante. La funcion de deteccion implementada, basada en la firma
mas fiable disponible para este ataque (una misma IP respondiendo desde
multiples MACs), demostro ser capaz de identificarlo de forma inmediata
y sin falsos positivos en condiciones normales, confirmando que, aunque
el ataque es sencillo de ejecutar, tambien lo es de detectar si se
monitoriza activamente el trafico ARP de la red.

El caso de bettercap merece una reflexion aparte: la imposibilidad de
hacerlo funcionar de forma fiable en este entorno concreto, pese a una
investigacion exhaustiva, ilustra un principio importante de la
seguridad ofensiva: las herramientas de alto nivel, por muy potentes y
populares que sean, dependen de asunciones sobre el entorno (deteccion
de gateway, estabilidad de la cache interna de hosts) que pueden no
cumplirse en todos los contextos, particularmente en redes
virtualizadas o en contenedores. Comprender el mecanismo subyacente (en
este caso, la construccion manual de paquetes ARP con scapy) resulto ser
no solo una alternativa valida, sino una demostracion de comprension mas
profunda que depender unicamente de una herramienta de terceros.

En el caso del DNS snooping y el ataque de Kaminsky, la deteccion basada
en umbral de respuestas NXDOMAIN demostro ser una firma sencilla pero
efectiva para identificar rafagas de reconocimiento o intentos de
envenenamiento de cache. La eleccion de un umbral y una ventana temporal
adecuados resulta critica: un umbral demasiado bajo generaria falsos
positivos con trafico DNS legitimo (errores tipograficos, aplicaciones
mal configuradas), mientras que uno demasiado alto podria no detectar
ataques mas lentos y distribuidos en el tiempo, precisamente para evadir
sistemas de deteccion como el implementado.

Desde una perspectiva de seguridad defensiva, ambos casos refuerzan la
misma leccion: la deteccion basada en anomalias de comportamiento (una
IP con multiples MACs, un volumen anormal de fallos de resolucion) es
mas robusta frente a variaciones en la tecnica de ataque que depender de
firmas especificas de una herramienta concreta, ya que el patron de
comportamiento anomalo persiste independientemente de si el atacante usa
bettercap, scapy, o cualquier otra implementacion del mismo ataque
subyacente.

= Bibliografia
<bibliografia>

#bibliography("bibliography.bib", title: none, style: "ieee")
