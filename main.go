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

		session, err := store.Get(c.Request, "logged-users")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		if _, ok := session.Values["id"]; ok {
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
		session.Values["new"] = true
		session.Save(c.Request, c.Writer)
		c.Redirect(301, "/register/second")
	})

	r.GET("/register/second", func(c *gin.Context) {
		session, err := store.Get(c.Request, "logged-users")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		if _, ok := session.Values["user"]; ok {
			c.Redirect(301, "/login/second")
			return
		}
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

		c.HTML(200, "second.tmpl", nil)
	})

	personalOnly := r.Group("/app")

	personalOnly.Use(func(c *gin.Context) {
		session, err := store.Get(c.Request, "cookie")
		if err != nil {
			c.AbortWithStatus(500)
			return
		}

		_, hasUser := session.Values["user"]
		_, hasTwofactor := session.Values["twofactor"]

		if hasUser && hasTwofactor {
			c.Next()
			return
		}

		c.Redirect(301, "/login")

	})

	// Listen and serve on 0.0.0.0:8080
	r.Run(":8080")
}
