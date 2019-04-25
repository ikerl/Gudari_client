# Gudari client

## Autores
**Servidor Gudari (C++):**
- **ikerl**

**Cliente Gudari (Python):**
-	Lógica básica y arreglos: **ikerl**
-	Programación de la interfaz de usuario e integración de opciones: **ompamo**

[https://github.com/ompamo](https://github.com/ompamo)

[https://github.com/ikerl](https://github.com/ikerl)

## Resumen:

Gudari es una herramienta para controlar equipos remotamente (RAT) que tiene como objetivo agilizar el proceso de pentesting en equipos Windows. Para ello, cuenta con un set de herramientas que nos ahorrarán bastantes dolores de cabezas y evitará el uso de herramientas de terceros. Es mi primer desarrollo de este tipo y servirá como base sólida para futuros proyectos. 
![](https://raw.githubusercontent.com/ikerl/Gudari_client/master/src/welcome.png)

## Características

-	**Estilo metasploit:**

El cliente de Gudari usa el mismo set de comandos que Metasploit haciendo que su uso sea natural desde el primer momento. Entre esos comandos están “SHOW OPTIONS”, “SET”, “RUN/EXPLOIT”, “SHELL”, etc..

 
 ![](https://raw.githubusercontent.com/ikerl/Gudari_client/master/src/options.png)
 
-	**Shell principal con soporte de cifrado RC4**

La Shell principal de Gudari se puede configurar para que use cifrado RC4. Para ello solo hay que activar la opción RC4 en “true” y establecer la contraseña de cifrado del servidor Gudari.

-	**Transferencia de ficheros**

Una vez que configuremos las opciones “LDIR” (directorio local) y “RDIR” (directorio remoto) podemos subir y bajar ficheros usando los comandos “UPLOAD” y “DOWNLOAD”
-	**Port forwarding**

Con el comando forward podemos mapear puertos remotos de la máquina gestionada en local. Estos mapeos soportan multithreading permitiendo múltiples conexiones simultáneamente.

-	**Shell interactiva**

-	**Powershell interactiva**

 ![](https://raw.githubusercontent.com/ikerl/Gudari_client/master/src/help.png)

## Integración:

Una de las partes más importantes de Gudari es su integración con los diferentes módulos que incluye. Podemos crear, borrar o mirar Shell y port forwardings en cualquier momento y podemos cambiar de tipo de Shell simplemente haciendo un “SET SESSION” e indicando la sesión que queremos controlar.

![](https://raw.githubusercontent.com/ikerl/Gudari_client/master/src/sessions.png)

![](https://raw.githubusercontent.com/ikerl/Gudari_client/master/src/fwds.png)
