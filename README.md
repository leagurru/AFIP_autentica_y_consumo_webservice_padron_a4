Ejemplo en python 3.12 para la Autenticación y autorización para utilizar
los webservices de la AFIP en modo homologación.

Ejemplo de la consulta al padrón de contribuyentes (webservice: ws_sr_padron_a4)
y obtención de la respuesta de AFIP a un CUIT, a partir de una lista de cuils cuits de prueba proporcionados por la AFIP

Instalación de requerimientos: 
pip install -r requirements.txt

config.ini.dev -> config.ini

config.ini: Se deben definir las constantes, especialmente el certificado y la clave privada y el cuil,
los que se deben obtener tal como lo indica la documentación oficial de la AFIP


Documentación AFIP:
WSAA (Webservice de Autenticación y Autorización)
url: https://www.afip.gob.ar/ws/documentacion/wsaa.asp

Especificación Técnica del WebService de Autenticación y Autorización (WSAA): 
http://www.afip.gob.ar/ws/WSAA/Especificacion_Tecnica_WSAA_1.2.2.pdf

Manual del Usuario del WSASS: 
http://www.afip.gob.ar/ws/WSASS/WSASS_manual.pdf
Ejemplos open source de clientes del WSAA (PHP, Java, .NET, PowerShell

Catálogo de web services:
https://www.afip.gob.ar/ws/documentacion/catalogo.asp

AFIP: Consulta al padrón de contribuyentes
Manual del desarrollador
id del servicio: ws_sr_padron_a4
https://www.afip.gob.ar/ws/ws_sr_padron_a4/manual_ws_sr_padron_a4_v1.3.pdf


Lista de CUITs/CUILs publicados por AFIP para pruebas: 
http://www.afip.gob.ar/ws/ws_sr_padron_a4/datos-prueba-padron-a4.txt


CÓMO GENERAR UNA SOLICITUD DE CERTIFICADO (CSR):
https://www.afip.gob.ar/ws/WSASS/html/generarcsr.html


