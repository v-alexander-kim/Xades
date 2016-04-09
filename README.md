# Xades
Xades Kit for GIS JKH - Fork from Microsoft France

Русский:
Данный проект представляет собой библиотеку для осуществления подписи в формате XAdES. Основной сценарий работы данной библиотеки – подпись сообщений для последующей отправки их в государственную информационную систему жилищно-коммунального хозяйства (ГИС-ЖКХ). Необходимо отметить, что ГИС-ЖКХ задает ограничения по форматам алгоритмов шифрования и хеширования, а именно, алгоритм подписи должен быть ГОСТ Р 34.11/34.10-2001 (Signature Algorithm: GOST R 34.11-94 with GOST R 34.10-2001).

Библиотека также предоставляет функционал по клиент-серверной реализации подписи сообщения в формате XAdES. 

Основной пример – TestIntegrationClientServer (https://github.com/springjazzy/Xades/blob/master/Source/UnitTestProject/TestIntegrationClientServer.cs).


* [Общий чат](https://gitter.im/springjazzy/GIS_JKH_Integration) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/springjazzy/GIS_JKH_Integration?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)


English:
This solution is a library for XAdES-based signing. Its primary use-case is to sign messages for subsequent sending them to State Information System of Housing and Communal Services (GIS-JKH). It should be noted that GIS-JKH restricts public key encryption and hash algorithms to GOST R 34.11-94 and GOST R 34.10-2001.

This library provides functionality needed for client-server realization of XAdES-based signing of messages.


* [Public chat room](https://gitter.im/springjazzy/GIS_JKH_Integration) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/springjazzy/GIS_JKH_Integration?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

The main example is TestIntegrationClientServer (https://github.com/springjazzy/Xades/blob/master/Source/UnitTestProject/TestIntegrationClientServer.cs).

