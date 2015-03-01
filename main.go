package main

import (
	"crypto/sha512"
	"fmt"
	"github.com/craigmj/gototp"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"math/rand"
	"os"
	"strconv"
	"time"
)

type LoginForm struct {
	Email    string `form:"email" binding:"required"`
	Password string `form:"password" binding:"required"`
}

type RegisterForm struct {
	Name     string `form:"name" binding:"required"`
	Email    string `form:"email" binding:"required"`
	Password string `form:"password" binding:"required"`
}

type CodeForm struct {
	Code string `form:"code" bindind:"required"`
}

type User struct {
	ID       int
	Name     string
	Email    string `sql:"type:varchar(200);"`
	TOTP     string `sql:"type:varchar(16);"`
	Password string `sql:"type:varchar(512)"`
}

type Configuration struct {
	DbType         string //MySQL o SQLite
	DbConfigString string //El string como parametro para gorm#Open
	Port           string //El puerto donde hacer el bind
}

func main() {
	//Servidor
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	conf := getConfiguration()

	//DB
	db, err := gorm.Open(conf.DbType, conf.DbConfigString)
	if err != nil {
		panic(err)
	}

	//Creamos la tabla
	db.CreateTable(&User{})

	//Cookies para la sesión
	var store = sessions.NewCookieStore([]byte("shhhh!"))
	if err != nil {
		panic(err)
	}

	//Home
	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.tmpl", nil)
	})

	//Register
	r.GET("/register", func(c *gin.Context) {
		c.HTML(200, "register.tmpl", nil)
	})

	r.POST("/register", func(c *gin.Context) {
		var form RegisterForm
		var user User

		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		if _, ok := session.Values["user"]; ok {
			c.Redirect(301, "/login/second")
			return
		}

		c.BindWith(&form, binding.Form)

		if !db.Where("email = ?", form.Email).First(&user).RecordNotFound() {
			c.HTML(200, "register.tmpl", gin.H{"error": "El E-Mail ya esta siendo utilizado"})
			return
		}

		pwd := sha512.Sum512([]byte(form.Password))

		rnd := rand.New(rand.NewSource(time.Now().Unix()))
		TOTP := gototp.RandomSecret(0, rnd)

		user = User{
			Name:     form.Name,
			Email:    form.Email,
			Password: fmt.Sprintf("%x", pwd[:]),
			TOTP:     TOTP,
		}

		db.Create(&user)
		session.Values["user"] = user.ID

		//Usamos esta variable para mostrarle el código QR al usuario por única vez
		session.Values["new"] = 1
		session.Save(c.Request, c.Writer)
		c.Redirect(301, "/register/second")
	})

	r.GET("/register/second", func(c *gin.Context) {
		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		userId, okUser := session.Values["user"]
		_, okNew := session.Values["new"]

		if !okUser || !okNew {
			c.Redirect(301, "/login/second")
			return
		}

		var user User
		if db.First(&user, userId).RecordNotFound() {
			//Si no podemos encontrar al usuario, redireccionamos al /logout
			//Es una condición rara, solo debería suceder si entre el login y el ingreso del código
			//el usuario fue borrado de la db
			c.Redirect(301, "/logout")
			return
		}

		otp, err := gototp.New(user.TOTP)
		if err != nil {
			c.AbortWithStatus(500)
		}

		qrUrl := otp.QRCodeGoogleChartsUrl("TOTP "+user.Email, 300)

		//Borramos la variable new para no mostrar de nuevo el código
		delete(session.Values, "new")
		session.Save(c.Request, c.Writer)

		c.HTML(200, "qr.tmpl", gin.H{"qrUrl": qrUrl})
	})

	//Login
	r.GET("/login", func(c *gin.Context) {
		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		if _, ok := session.Values["user"]; ok {
			c.Redirect(301, "/login/second")
			return
		}

		c.HTML(200, "login.tmpl", nil)
	})

	r.POST("/login", func(c *gin.Context) {
		var form LoginForm
		var user User

		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		_, ok := session.Values["user"]
		if ok {
			c.Redirect(301, "/login/second")
			return
		}

		c.BindWith(&form, binding.Form)
		if db.Where("email = ?", form.Email).First(&user).RecordNotFound() {
			c.HTML(200, "login.tmpl", gin.H{"error": "Usuario o contraseña incorrecto/s"})
			return
		}

		if pwd := sha512.Sum512([]byte(form.Password)); fmt.Sprintf("%x", pwd[:]) != user.Password {
			c.HTML(200, "login.tmpl", gin.H{"error": "Usuario o contraseña incorrecto/s"})
			return
		}

		session.Values["user"] = user.ID

		session.Save(c.Request, c.Writer)
		c.Redirect(301, "/login/second")
	})

	r.GET("/login/second", func(c *gin.Context) {
		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		if _, ok := session.Values["user"]; !ok {
			c.Redirect(301, "/login")
			return
		}

		if _, ok := session.Values["twofactor"]; ok {
			c.Redirect(301, "/app/secret")
			return
		}

		c.HTML(200, "second.tmpl", nil)
	})

	r.POST("/login/second", func(c *gin.Context) {
		var form CodeForm
		c.BindWith(&form, binding.Form)

		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		userId, ok := session.Values["user"]
		if !ok {
			c.Redirect(301, "/login")
			return
		}

		var user User

		db.First(&user, userId)
		otp, err := gototp.New(user.TOTP)
		if nil != err {
			c.AbortWithStatus(500)
		}

		code64, err := strconv.ParseInt(form.Code, 0, 32)
		if err != nil {
			c.HTML(200, "second.tmpl", gin.H{"error": "Código Incorrecto"})
			return
		}

		code := int32(code64)

		//Usamos el código anterior y el siguiente para tener en cuenta las diferencias de tiempo entre el servidor
		//y el cliente
		before := otp.FromNow(-1)
		now := otp.Now()
		after := otp.FromNow(1)

		if code != before && code != now && code != after {
			c.HTML(200, "second.tmpl", gin.H{"error": "Código Incorrecto"})
			return
		}

		//Seteamos la cookie para indentificarlo como autenticado
		session.Values["twofactor"] = true
		session.Save(c.Request, c.Writer)
		c.Redirect(301, "/app/secret")
	})

	//Logout
	r.GET("/logout", func(c *gin.Context) {
		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		if _, ok := session.Values["user"]; !ok {
			c.Redirect(301, "/")
			return
		}

		//Borramos la session
		delete(session.Values, "user")
		delete(session.Values, "twofactor")
		session.Save(c.Request, c.Writer)

		c.Redirect(301, "/")
	})

	r.GET("/app/secret", func(c *gin.Context) {
		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		_, okUser := session.Values["user"]
		_, okTwo := session.Values["twofactor"]

		if !okUser || !okTwo {
			c.Redirect(301, "/login")
			return
		}

		c.HTML(200, "secret.tmpl", nil)
	})

	//Escuchamos en el puerto en $PORT o el 8080
	r.Run(":" + conf.Port)
}

func getConfiguration() Configuration {
	conf := Configuration{}

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
	}

	conf.Port = port

	mysqlString := os.Getenv("MYSQL_STRING")

	//Si esta definido mysql, lo usamos
	if len(mysqlString) != 0 {
		conf.DbType = "mysql"
		conf.DbConfigString = mysqlString
		return conf
	}

	sqlitePath := os.Getenv("SQLITE_PATH")
	if len(sqlitePath) == 0 {
		sqlitePath = "/tmp/two-factor.db"
	}

	conf.DbType = "sqlite3"
	conf.DbConfigString = sqlitePath

	return conf
}
