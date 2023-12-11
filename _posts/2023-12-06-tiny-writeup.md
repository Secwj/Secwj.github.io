---
title: Tiny - HackMyVM Writeup
date: 2023-12-06
categories: [Writeups, HMV]
tags: [Linux, Sql Injection, Information Leakage, Wordpress Enumeration, PrivEsc, Password Brute force]
---
![](/assets/img/Tiny/tiny.png)

Hola a todos! El día de hoy vamos a resolver una máquina realmente interesante creada por [cromiphi](https://www.youtube.com/@cromiphi). Esta es una máquina Linux de 
dificultad Hard.

## Enumeración
---
### Puertos

Comenzamos el escaneo de puertos con `nmap`:
```bash
nmap -p- --open -sS --min-rate 5000 -n -vvv -Pn 192.168.101.10 -oG allports
```

#### Opciones Utilizadas en el `escaneo`:
- `-p-`: Escaneo de los 65535 puertos.
- `--open`: Filtrar por aquellos puertos que tienen un estado abierto.
- `-sS`: Realizar un escaneo de tipo "TCP SYN". Si recibe un paquete SYN/ACK de vuelta, indica que el puerto está abierto. Si recibe un paquete de tipo RST (reset), significa que el puerto está cerrado.
- `--min-rate 5000`: Lanzar 5000 paquetes por segundo.
- `-n`: No realizar una resolución DNS.
- `-vvv`: Mostrar por pantalla información del escaneo.
- `-Pn`: No realizar un (host discovery) de la ip de la máquina víctima
- `192.168.101.10`: Ip de la maquina víctima
- `-oG allports` : Guardar la salida del escaneo en formato Greppable en el archivo allports.

![](/assets/img/Tiny/escaneo.png)

Utilizamos el la utilidad extractPorts del señor [savitar](https://github.com/s4vitar)  para extraer los puertos y
tenerlos copiados en la clipboard.

```bash
  extractPorts allports
```
![](/assets/img/Tiny/ports.png)

Procedemos a realizar un escaneo de versiones y lanzar algunos scripts de enumeracion.

```bash
nmap -p22,80,8888 -sCV -vvv 192.168.101.10 -oN targeted
```
#### Opciones utilizadas en el `escaneo`:
- `-p22,80,8888`: Especificamos los puertos a escanear.
- `-sCV`: Lanzamos el escaneo de versiones con el parametro "V" y de scripts con el parametro "C":
- `-vvv`: Mostrar por pantalla información del escaneo.
- `192.168.101.10`: Ip de la máquina víctima.
- `-oN targeted`: Guardar la salida del escaneo en formato Nmap en el archivo targeted.

![](/assets/img/Tiny/versiones.png)

De los resultados obtenidos vamos a enumerar el puerto 80.

## Web

Enumeramos las tecnologias de la web mediante `whatweb`.
```bash
whatweb http://192.168.101.10
```
![](/assets/img/Tiny/whatweb.png)

Vemos que nos reporta una version de WordPress 6.4.2. Podemos buscar un exploit con `searchsploit`.

![](/assets/img/Tiny/searchsploit.png)

Nos reporta varios exploit, pero no para la versión especifica del WordPress que buscamos.

Ahora nos dirigimos a la pagina web.

![](/assets/img/Tiny/pagina_web.png)

Podemos ver la pagina típica de Wordpress, pero sin los estilos. Veamos el codigo fuente de la pagina con Ctrl + U.

![](/assets/img/Tiny/virtual-hosting.png)


Encontramos que la pagina esta cargando el contenido del dominio `tiny.hmv`. Entonces se esta aplicando virtual hosting.
- `virtual hosting`: El Virtual Hosting (o alojamiento virtual) es una técnica que permite que múltiples sitios web compartan un solo servidor físico, pero aparezcan como si estuvieran alojados en servidores independientes


Agregamos el dominio a nuestro /etc/hosts para que resuelva correctamente.
