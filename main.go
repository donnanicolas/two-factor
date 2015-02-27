package main

import (
	"crypto/sha512"
	"github.com/craigmj/gototp"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"math/rand"
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
	ID        int
	Name      string
	Email     string `sql:"type:varchar(200);"`
	TOTP      string `sql:"type:varchar(16);"`
	Password  string `sql:"type:varchar(512)"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func main() {
	//Server
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	//DB
	db, err := gorm.Open("sqlite3", "/tmp/two-factor.db")
	if err != nil {
		panic(err)
	}

	//Create Table
	db.CreateTable(&User{})

	//Session Store
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
			Password: string(pwd[:]),
			TOTP:     TOTP,
		}

		db.Create(&user)
		session.Values["user"] = user.ID
		//We flag the user as new so we can show him the QR code
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
			//If we can't find the user we logout
			//This is a rare condition, can happen when a record has been deleted
			c.Redirect(301, "/logout")
			return
		}

		otp, err := gototp.New(user.TOTP)
		if err != nil {
			c.AbortWithStatus(500)
		}

		code := otp.Now()
		qrUrl := otp.QRCodeGoogleChartsUrl("TOTP", 300)

		c.HTML(200, "qr.tmpl", gin.H{"code": code, "qrUrl": qrUrl})
	})

	//Login
	r.GET("/login", func(c *gin.Context) {
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

		if _, ok := session.Values["user"]; ok {
			c.Redirect(301, "/login/second")
			return
		}

		c.BindWith(&form, binding.Form)
		if db.Where("email = ?", form.Email).First(&user).RecordNotFound() {
			c.HTML(200, "login.tmpl", gin.H{"error": "Usuario o contraseña incorrecto/s"})
			return
		}

		if pwd := sha512.Sum512([]byte(form.Password)); string(pwd[:]) != user.Password {
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

		//We use the code from before and after to take in account time differences between the device and the server
		before := otp.FromNow(-1)
		now := otp.Now()
		after := otp.FromNow(1)

		if code != before && code != now && code != after {
			c.HTML(200, "second.tmpl", gin.H{"error": "Código Incorrecto"})
			return
		}

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

		//Delete the session)
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

	// Listen and serve on 0.0.0.0:8080
	r.Run(":8080")
}
