Zeep: Python SOAP client
https://docs.python-zeep.org/en/master/
--------------------------------------------------------------------------------------
AFIP: WSAA (Webservice de Autenticación y Autorización)
https://www.afip.gob.ar/ws/documentacion/wsaa.asp
--------------------------------------------------------------------------------------
AFIP: Consulta al padrón de contribuyentes
Manual del desarrollador
id del servicio: ws_sr_padron_a4
https://www.afip.gob.ar/ws/ws_sr_padron_a4/manual_ws_sr_padron_a4_v1.3.pdf
--------------------------------------------------------------------------------------


Lista de CUITs publicados por AFIP para pruebas:  http://www.afip.gob.ar/ws/ws_sr_padron_a4/datos-prueba-padron-a4.txt

WSASS: certificado
https://wsass-homo.afip.gob.ar/wsass/portal/main.aspx


CÓMO GENERAR UNA SOLICITUD DE CERTIFICADO (CSR):
https://www.afip.gob.ar/ws/WSASS/html/generarcsr.html

openssl genrsa -out certificado_csr.pk 2048
genera archivo con pk

openssl req
    -new
    -key MiClavePrivada
    -subj "/C=AR/O=subj_o/CN=subj_cn/serialNumber=CUIT subj_cuit"
    -out MiPedidoCSR

donde hay que reemplazar:

MiClavePrivada por nombre del archivo elegido en el primer paso.
subj_o por el nombre de su empresa
subj_cn por el nombre de su sistema cliente
subj_cuit por la CUIT (sólo los 11 dígitos, sin guiones) de la empresa o del programador (persona jurídica)
MiClavePrivada por el nombre del archivo de la clave privada generado antes
MiPedidoCSR por el nombre del archivo CSR que se va a crear


Por ejemplo, para una empresa llamada EmpresaPrueba, un sistema TestSystem, la CUIT 20123456789, con el archivo MiClavePrivada generado en el punto anterior:

openssl req
-new
-key MiClavePrivada
-subj "/C=AR/O=EmpresaPrueba/CN=TestSystem/serialNumber=CUIT 20123456789"
-out MiPedidoCSR


Por ejemplo, para una empresa llamada EmpresaPrueba, un sistema TestSystem, la CUIT 20123456789, con el archivo MiClavePrivada generado en el punto anterior:

openssl req -new -key certificado_csr.pk -subj "/C=AR/O=PJN_CNAT/CN=AFIP_Consulta_Padron/serialNumber=CUIT 20171070652" -out 20171070652.csr

esto generó un archivo



Web Service padron a4: "ws_sr_padron_a4": "https://awshomo.afip.gov.ar/sr-padron/webservices/personaServiceA4?WSDL",


 datos testing:
 https://www.afip.gob.ar/ws/ws_sr_padron_a4/datos-prueba-padron-a4.txt