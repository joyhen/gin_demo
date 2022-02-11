package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"html/template"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	//demo1()
	demo2()
	//demo3()
	//demo4()
	//demo_postdata()
	//demo_postdata2()
	//post_file()
}

func demo1() {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		//c.JSON(200, gin.H{
		//	"message": "pong",
		//})

		data := map[string]interface{}{
			"lang": "go语言",
			"tag":  "<br>",
		}
		// 输出 : {"lang":"go\u8bed\u8a00","tag":"\u003cbr\u003e"}
		c.AsciiJSON(http.StatusOK, data)
	})
	r.Run() // 监听并在 0.0.0.0:8080 上启动服务

	//访问：http://localhost:8080/ping
	//回应：{"message":"pong"}
}

const STATIC_PATH string = "src/static"
const TEMPLATE_PATH string = "src/template/**/*"

// https://zhuanlan.zhihu.com/p/404916623
func demo2() {
	var (
		currentDoc   string
		staticPath   string
		templatePath string
		engine       *gin.Engine
		//
		title    string
		dateTime time.Time
	)

	currentDoc = os.Getenv("GOPATH")
	//dir, _ := os.Getwd()
	//templatePath = filepath.Join(dir, TEMPLATE_PATH)
	templatePath = filepath.Join(currentDoc, TEMPLATE_PATH)
	staticPath = filepath.Join(currentDoc, STATIC_PATH)

	//=============================================================
	engine = gin.Default()
	//engine.Delims("{[{", "}]}") //自定义分隔符

	engine.SetFuncMap(template.FuncMap{
		"formatAsDate": formatAsDATE,
	})

	engine.LoadHTMLGlob(templatePath)
	//engine.LoadHTMLFiles(loadTmplFiles(TEMPLATE_DIR)...)
	//配置静态文件夹路径：第一个参数是api，第二个参数是文件夹路径
	engine.StaticFS("/static", http.Dir(staticPath))

	title = "my first go language website"
	dateTime = time.Date(2022, 02, 11, 13, 33, 46, 0, time.UTC)

	//嵌套
	engine.GET("/index", func(context *gin.Context) {
		context.HTML(http.StatusOK, "index.tmpl", gin.H{
			"title":      title,
			"createTime": dateTime,
		})
	})

	//嵌套+继承（实现模板中的定义模板）
	engine.GET("/index/user", func(context *gin.Context) {
		context.HTML(http.StatusOK, "user.tmpl", gin.H{
			"title": "我是内容页面（模板继承测试）",
		})
	})

	engine.Run(":8080")
}

// 格式化时间输出
func formatAsDATE(t time.Time) string {
	year, month, day := t.Date()
	return fmt.Sprintf("%d/%02d/%02d", year, month, day)
}

type User struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func demo3() {
	var (
		engine *gin.Engine
		user   *User
	)

	engine = gin.Default()
	engine.Use(CrossHandler()) //跨域

	//engine.Static("/static", "./static")
	//engine.StaticFS("favicon.ico", http.Dir("./static"))

	engine.GET("/user", func(context *gin.Context) {
		user = &User{
			ID:   1,
			Name: "tony",
			Age:  29,
		}
		//{"id":1,"name":"tony","age":29}
		context.JSON(http.StatusOK, user)
	})
	engine.Run(":8080")
}

func loadTmplFiles(tmplPath string) []string {
	var files []string
	filepath.Walk(tmplPath, func(path string, info fs.FileInfo, err error) error {
		if strings.HasPrefix(path, ".tmpl") {
			files = append(files, path)
		}
		return nil
	})

	return files
}

// CrossHandler 跨域访问：cross  origin resource share
func CrossHandler() gin.HandlerFunc {
	return func(context *gin.Context) {
		method := context.Request.Method
		context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		context.Header("Access-Control-Allow-Origin", "*") // 设置允许访问所有域
		context.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE")
		context.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session,X_Requested_With,Accept, Origin, Host, Connection, Accept-Encoding, Accept-Language,DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Pragma,token,openid,opentoken")
		context.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers,Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma,FooBar")
		context.Header("Access-Control-Max-Age", "172800")
		context.Header("Access-Control-Allow-Credentials", "false")
		context.Set("content-type", "application/json") // 设置返回格式是json

		// 放行所有OPTIONS方法
		if method == "OPTIONS" {
			context.AbortWithStatus(http.StatusNoContent)
		}

		//if method == "OPTIONS" {
		//	context.JSON(http.StatusOK, map[string]interface{}{
		//		"Code": 0,
		//		"Data": "Options Request!",
		//	})
		//}

		//处理请求
		context.Next()
	}
}

func demo4() {
	var (
		tmpl   *template.Template
		engine *gin.Engine
	)

	tmpl = template.Must(template.New("https").Parse(`
<html>
<head>
  <title>Https Test</title>
  <script src="/static/js/app.js"></script>
</head>
<body>
  <h1 style="color:red;">Welcome, Ginner!</h1>
</body>
</html>
`))

	engine = gin.Default()
	engine.SetHTMLTemplate(tmpl)
	engine.GET("/", func(context *gin.Context) {
		if pusher := context.Writer.Pusher(); pusher != nil {
			if err := pusher.Push("/static/js/app.js", nil); err != nil {
				log.Printf("failed to push: %v", err)
			}
		}

		context.HTML(200, "https", gin.H{
			"status": "success",
		})
	})

	engine.RunTLS(":8080", "./crt/server.pem", "./crt/server.key")
}

func demo_jsonp() {
	engine := gin.Default()
	engine.GET("/JSONP", func(context *gin.Context) {
		data := map[string]interface{}{
			"foo": "bar",
		}
		// /JSONP?callback=x
		// 将输出：x({\"foo\":\"bar\"})
		context.JSONP(http.StatusOK, data)
	})

	engine.Run(":8080")
}

type LoginForm struct {
	User     string `form:"user" binding:"required"`
	Password string `form:"password" binding:"required"`
}

func demo_postdata() {
	var (
		engine    *gin.Engine
		logindata *LoginForm
	)

	engine = gin.Default()
	engine.POST("/login", func(context *gin.Context) {
		logindata = &LoginForm{}
		if context.ShouldBind(logindata) == nil {
			if logindata.User == "user" && logindata.Password == "123" {
				context.JSON(200, gin.H{
					"status": "you ar logged in",
				})
			} else {
				context.JSON(401, gin.H{
					"status": "unauthorized",
				})
			}
		}
	})

	engine.Run(":8080")
}

func demo_postdata2() {
	engine := gin.Default()
	//engine.SecureJsonPrefix("')]},\n") //自定义 SecureJSON 前缀

	engine.POST("/form_post", func(context *gin.Context) {
		//id := context.Query("id")
		//id := context.DefaultQuery("id", "125")
		message := context.PostForm("message")
		nick := context.DefaultPostForm("nick", "none")
		//context.JSON(200, gin.H{
		//	"status":  "posted",
		//	"message": message,
		//	"nick":    nick,
		//})

		data := []string{message, nick, "foo"}
		context.SecureJSON(200, data) //默认 while(1);前缀

		//带有html标签输出
		//context.JSON(200, gin.H{
		//	"html":    "<b>Hello, world!</b>",
		//	"message": message,
		//	"nick":    nick,
		//})

		//html标签转unicode输出
		//context.PureJSON(200, gin.H{
		//	"html":    "<b>Hello, world!</b>",
		//	"message": message,
		//	"nick":    nick,
		//})
	})

	engine.POST("/form_post2", func(context *gin.Context) {
		context.SecureJSON(200, []string{"11", "22", "33"})
	})

	engine.GET("/xml", func(context *gin.Context) {
		context.XML(200, gin.H{
			"message": "hey",
		})
	})
	engine.GET("/yaml", func(context *gin.Context) {
		context.YAML(200, gin.H{
			"where": map[string]interface{}{
				"he": "111",
				"pp": 456,
			},
			"age": 30,
		})
	})

	engine.Run(":8080")
}

func post_file() {
	var (
		file *multipart.FileHeader
		err  error
	)

	engine := gin.Default()

	currentDoc := os.Getenv("GOPATH")
	uploadDoc := filepath.Join(currentDoc, "src/upload")

	engine.MaxMultipartMemory = 8 << 20 //8m
	engine.POST("/upload", func(context *gin.Context) {
		if file, err = context.FormFile("file"); err != nil {
			context.String(200, fmt.Sprintf("error:%s", err.Error()))
		}

		filename := file.Filename
		filepath := uploadDoc + "/" + filename

		if _, err = os.Stat(uploadDoc); os.IsNotExist(err) {
			os.Mkdir(uploadDoc, os.ModeDir)
		}
		if err = context.SaveUploadedFile(file, filepath); err != nil {
			context.String(200, fmt.Sprintf("error:%s", err.Error()))
		}
		context.String(200, fmt.Sprintf("%s uploaded!", filename))
	})

	engine.Run(":8080")
}
