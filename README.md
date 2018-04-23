
# Proyecto Seguridad del Software

### Control	 de	 acceso:	 
Permitir	 el	 registro	 inicial	 y	 posterior	 autenticación	 de	 un	
usuario	 con	 una	 contraseña	 segura	 (de	 mínimo	 8	 caracteres	 con	 al	 menos	 1	
número,	1	minúscula,	1	mayúscula	y	1	especial).	Esta	información	deberá	ir	a	una	
tabla	(en	una	BD	de	prueba)	que	debe	contener	como	mínimo	nombre	de	usuario	
(login),	nombre	y	apellido	del	usuario	y	contraseña	almacenada	en	hash	SHA-1.	
   
Una	 vez	 autenticado	 el	 usuario	 deberá	 disponer	 de	 un	 menú	 con	 las	 siguientes	
opciones	adicionales:

### Password hash (SHA-1)
• Visible desde el home page	(para	verificación	de	hash)   
### Encrypt/decrypt file AES
• Cifrado/descifrado	de	un	archivo	en	AES	a	partir	del	ingreso	del	archivo	y	
una	llave	dada.
### Digital Signature
• Firma/validación de	 Firma,	 a	 partir de	 una	 pareja	 de	 llaves	 pública	 y	
privada	 (las	 cuales	 deben	 ser	generadas	inicialmente) y	 un	archivo	 dado.
Emplear	como	algortimo	de	hash	MD5	y	de	crifrado	RSA	para	la	generación	
de	la	firma.
### Cerrar sesion
• Opción	de	salida	segura	(cierre	de	sesión).
### Requerimientos otros
• La	 aplicación	 deberá	 ser	 publicada	 a	 través	 de	internet	 con	 el	 fin	 de	 permitir	 su	
acceso	y	evaluación.   
• Los	 archivos	 correspondientes	 al	 código	 fuente	 deberán	 ser	 cargados	 en	 el	
catálogo	en	formato	comprimido.
