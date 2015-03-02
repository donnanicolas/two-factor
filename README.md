#TOTP
Este es un proyecto para la Universidad de Mendoza.
El mismo es una simple aplicación que implemente doble autenticación vía Google Authenticator.

La aplicación está programada en [Go](http://golang.org/)

##Compilación
Para poder compilar la aplicación se debe contar con la herramienta [go](https://golang.org/cmd/go/) y godep instalado
https://github.com/tools/godep

Para compilar la aplicación correr
```bash
godep go build
```

##Correr el servicio
El servidor puede ser utilizado con MySQL o SQLite
Para utilizar MySQL, se debe simplemente setear la variable $MYSQL_STRING de acuerdo con lo explicado en https://github.com/go-sql-driver/mysql#dsn-data-source-name
Sino se puede utilzar SQLite seteando $SQLITE_PATH.
MySQL tiene precedencia sobre SQLite, o sea si están las dos seteadas se utilará MySQL
Si ninguna de estas variables existe se utilizara SQLite en el path /tmp/two-factor.db

El puerto puede ser cambiar seteando $PORT, por default corre en el puerto 8080

Para correr el servidor, simplemente hacer
```bash
./two-factor
```

##Utilizando la apliación Web
Para poder loguearse recuerde descargar Google Authenticator, ya que de lo contrario no podrá obtener los códigos.
Luego siga las instrucciones del sitio.


