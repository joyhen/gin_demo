// 参考：
// https://segmentfault.com/a/1190000017958702
// https://zhuanlan.zhihu.com/p/404916623
// https://blog.csdn.net/HuangZhang_123/article/details/100123821
// https://github.com/gin-gonic/examples
// https://juejin.cn/post/6957982755527344158
// 路由：https://www.cnblogs.com/paulwhw/p/14103123.html
// go http编程：https://www.cnblogs.com/itbsl/p/12175645.html
// gin web framework: https://gin-gonic.com/zh-cn/docs/examples/binding-and-validation/

package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/autotls"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/gin-gonic/gin/render"
	"github.com/go-playground/validator/v10"
	"golang.org/x/sync/errgroup"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	//demo1()
	//demo2()
	//demo3()
	//demo4()
	//demoPostData()
	//demoPostData2()
	//post_file()
	//postFiles()
	postFilesChan()
	//showImage()
	//demo5()
	//demo6()
	//demoRpc()

	//for i := 0; i < 20; i++ {
	//	fmt.Println(randomString(8))
	//}

	//demoPanic()
	//demoGoroutine()
	//renderCustomPage()
	//demo_jsonp()

	//NativeRed()
	//ginWithNative()
	//demoHttps()
	//demoBindingUri()

	//validatorDemo()
	//staticDemo()

	//multipleServerDemo()
}

//=====================运行多个服务===========================

var (
	g errgroup.Group
)

func router01() http.Handler {
	e := gin.New()
	e.Use(gin.Recovery())
	e.GET("/", func(c *gin.Context) {
		c.JSON(
			http.StatusOK,
			gin.H{
				"code":  http.StatusOK,
				"error": "Welcome server 01",
			},
		)
	})

	return e
}

func router02() http.Handler {
	e := gin.New()
	e.Use(gin.Recovery())
	e.GET("/", func(c *gin.Context) {
		c.JSON(
			http.StatusOK,
			gin.H{
				"code":  http.StatusOK,
				"error": "Welcome server 02",
			},
		)
	})

	return e
}

func multipleServerDemo() {
	server01 := &http.Server{
		Addr:         ":8080",
		Handler:      router01(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	server02 := &http.Server{
		Addr:         ":8081",
		Handler:      router02(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	g.Go(func() error {
		return server01.ListenAndServe()
	})

	g.Go(func() error {
		return server02.ListenAndServe()
	})

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

//===================================================

func staticDemo() {
	router := gin.Default()
	router.Static("/assets", "./assets")
	router.StaticFS("/more_static", http.Dir("upload"))
	router.StaticFile("/favicon.ico", "./static/favicon.ico")

	// 监听并在 0.0.0.0:8080 上启动服务
	router.Run(":8080")
}

// 验证库 https://github.com/go-playground/validator
// Booking 包含绑定和验证的数据。
type Booking struct {
	CheckIn  time.Time `form:"check_in" binding:"required,bookplates" time_format:"2006-01-02"`
	CheckOut time.Time `form:"check_out" binding:"required,gtfield=CheckIn,bookplates" time_format:"2006-01-02"`
}

var bookableDate validator.Func = func(fl validator.FieldLevel) bool {
	if date, ok := fl.Field().Interface().(time.Time); ok {
		today := time.Now()
		if today.After(date) {
			return false
		}
	}

	return true
}

func validatorDemo() {
	engine := gin.Default()

	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("bookplates", bookableDate)
	}

	engine.GET("/book", func(c *gin.Context) {
		var b Booking
		if err := c.ShouldBindWith(&b, binding.Query); err != nil {
			c.JSON(200, map[string]interface{}{
				"message": "booking dates are valid!",
			})
		} else {
			c.JSON(400, map[string]interface{}{
				"error": err.Error(),
			})
		}
	})

	engine.Run()
}

//===================================

type StructA struct {
	FieldA string `form:"field_a"`
}

type StructB struct {
	NestedStruct StructA
	FieldB       string `form:"field_b"`
}
type StructC struct {
	NestedStructPointer *StructA
	FieldC              string `form:"field_c"`
}
type StructD struct {
	//直接嵌套
	NestedAnonyStruct struct {
		FieldX string `form:"field_x"`
	}
	FieldD string `form:"field_d"`
}

type Student struct {
	ID   string `uri:"id" binding:"required,uuid"`
	Name string `uri:"name" binding:"required"`
}

func demoBindingUri() {
	engine := gin.Default()
	//http://localhost:8080/getb?field_a=hello&field_b=world
	engine.GET("/getb", func(c *gin.Context) {
		var b StructB
		c.Bind(&b)
		c.JSON(200, b)
	})
	//http://localhost:8080/getc?field_a=hello&field_c=world
	engine.GET("/getc", func(c *gin.Context) {
		var cc StructC
		c.Bind(&cc)
		c.JSON(200, cc)
	})
	//http://localhost:8080/getd?field_x=hello&field_d=world
	engine.GET("/getd", func(c *gin.Context) {
		var d StructD
		c.Bind(&d)
		c.JSON(200, d)
	})
	engine.GET("/:name/:id", func(c *gin.Context) {
		var student Student
		if err := c.ShouldBindUri(&student); err != nil {
			c.JSON(400, map[string]interface{}{
				"msg": err.Error(),
			})
			return
		}

		c.JSON(200, map[string]interface{}{
			"uuid": student.ID,
			"name": student.Name,
		})
	})
	engine.Run()
}

//配置https
func demoHttps() {
	r := gin.Default()

	// Ping handler
	r.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	log.Fatal(autotls.Run(r, "example1.com", "example2.com"))
}

func demoGoroutine() {
	var (
		f   *os.File
		err error
	)

	if f, err = os.Create("gin.log"); err != nil {
		panic(err)
	}

	gin.ForceConsoleColor()
	gin.DefaultWriter = io.MultiWriter(f, os.Stdout) //同时输出到控制台

	//gin.DisableConsoleColor()
	//gin.DefaultWriter = io.MultiWriter(f)

	//路由日志格式
	//gin.SetMode(gin.DebugMode)
	//gin.DebugPrintRouteFunc = func(httpMethod, absolutePath, handlerName string, nuHandlers int) {
	//	log.Printf("endpoint %v %v %v %v\n",
	//		httpMethod, absolutePath, handlerName, nuHandlers)
	//}

	engine := gin.Default()
	engine.GET("/login_async", func(c *gin.Context) {
		ccp := c.Copy() //创建副本
		go func() {
			// 模拟长任务
			time.Sleep(3 * time.Second)
			log.Println("done! in path " + ccp.Request.URL.Path)
		}()
		c.String(200, "back now")
	})

	engine.GET("/login_sync", func(c *gin.Context) {
		// 模拟长任务
		time.Sleep(3 * time.Second)
		log.Println("done! in path ", c.Request.URL.Path)
		c.String(200, "waiting")
	})

	//===========================接口版本==========================
	//// 简单的路由组: v1
	//v1 := engine.Group("/v1")
	//{
	//	v1.POST("/login", loginEndpoint)
	//	v1.POST("/submit", submitEndpoint)
	//	v1.POST("/read", readEndpoint)
	//}
	//
	//// 简单的路由组: v2
	//v2 := engine.Group("/v2")
	//{
	//	v2.POST("/login", loginEndpoint)
	//	v2.POST("/submit", submitEndpoint)
	//	v2.POST("/read", readEndpoint)
	//}

	//路由组
	groupShop := engine.Group("/shop")
	{
		// /shop/list
		groupShop.GET("/list", func(c *gin.Context) {
			////一个小时的cookie
			//c.SetCookie("hello", "val", 3600, "/", "localhost", true, true)
			//
			//c.Header("token", "123fds354fds1f") //设置请求头
			//lang := c.GetHeader("lan") //获取语言
			//if cookie, err := c.Request.Cookie("hello"); err != nil {
			//	c.String(200, cookie.Value, ": ", err.Error(), ", lang=", lang)
			//}

			c.JSON(http.StatusOK, gin.H{
				"msg": "shop.list",
			})
		})

		// /shop/list/product/11111
		groupShop.GET("/product/:id", func(c *gin.Context) {
			id := c.Param("id")
			c.JSON(http.StatusOK, gin.H{
				"msg": "shop.product:" + id,
			})
		})

		// 以 * 开头匹配匹配
		// /product/detail/123
		// /product/detail/123/info
		// /product/detail/123/author/info
		groupShop.GET("/product/detail/*id", func(c *gin.Context) {
			id := c.Param("id")
			c.JSON(http.StatusOK, gin.H{
				"product id": id,
			})
		})
	}

	engine.Run(":8080")
}

//=============================================================

func demoPanic() {
	//defer func() {
	//	if err := recover(); err != nil {
	//		fmt.Println("出了错：", err)
	//	}
	//}()
	//myPanic()

	//====================================

	safeGo(myPanic)
	time.Sleep(3 * time.Second)
	fmt.Printf("这里应该执行不到！")
}

func myPanic() {
	var x = 30
	var y = 0
	//panic("我就是一个大错误！")
	var c = x / y
	fmt.Println(c)
}

func safeGo(f func()) {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)
				//fmt.Println("出了错：", err)
			}
		}()

		f()
	}()
}

//=============================================================
// #随机数据

func randInt(min int, max int) int {
	return min + rand.Intn(max-min)
}
func randomString(l int) string {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(randInt(65, 90))
	}
	return string(bytes)
}

//=============================================================

type Listener int
type Reply struct {
	Data string
}

// #正对 Listener 类型定义了一个 GetLine 的rpc方法，Listener.GetLine
func (l *Listener) GetLine(line []byte, reply *Reply) error {
	rv := string(line)
	fmt.Printf("receive: %v\n", rv)
	*reply = Reply{rv}
	return nil
}

func demoRpc() {
	var (
		err     error
		add     *net.TCPAddr
		inbound *net.TCPListener
	)
	if add, err = net.ResolveTCPAddr("tcp", "0.0.0.0:12345"); err != nil {
		log.Fatal(err)
	}

	if inbound, err = net.ListenTCP("tcp", add); err != nil {
		log.Fatal(err)
	}

	listener := new(Listener)
	rpc.Register(listener)
	rpc.Accept(inbound)
}

//=============================================================
/* 测试 */
func demo6() {
	r := setupRouter()
	r.Run(":8080")
}

func setupRouter() *gin.Engine {
	r := gin.Default()
	r.GET("ping", func(c *gin.Context) {
		c.String(200, "pong")
	})
	return r
}

//=============================================================

type Person struct {
	Name    string `json:"name" form:"name"`
	Address string `json:"address" form:"address"`
}

func middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("username", "tony")
		c.Next()
	}
}

func demo5() {
	//gin.DisableConsoleColor()
	//gin.ForceConsoleColor()

	var (
		err error
	)

	engine := gin.Default()
	engine.GET("/fly", middleware(), func(c *gin.Context) {
		name := c.MustGet("username").(string)
		name2, _ := c.Get("username")

		var person Person
		//body=>raw=>json格式数据提交
		if err = c.ShouldBindBodyWith(&person, binding.JSON); err == nil {
			fmt.Println(person.Name)
			fmt.Println(person.Address)
		}

		//ShouldBindUri

		c.JSON(200, gin.H{
			"name":  name,
			"name2": name2,
		})
	})

	engine.Run(":8080")
}

func runMicServer() {
	engine := gin.Default()
	engine.GET("/", func(context *gin.Context) {
		time.Sleep(5 * time.Second)
		context.String(200, "welcome mic server")
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: engine,
	}

	go func() {
		// 服务连接
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// 等待中断信号以优雅地关闭服务器（设置 5 秒的超时时间）
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	<-quit //没信号会阻塞

	log.Println("shutdown server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("server shutdown:", err)
	}

	log.Println("server exiting")
}

func showImage() {
	var (
		url  string
		resp *http.Response
		//req  *http.Request
		err error
	)

	engine := gin.Default()
	engine.GET("/get_image", func(context *gin.Context) {
		url = "http://img.dm747.com/bjm3u8/upload/vod/20220126-20u/c36a9bc0d0f91fd707da52ab282e97cc.jpg"
		//if req, err = http.NewRequest("GET", url, nil); err != nil {
		//	fmt.Println(err.Error())
		//}
		////req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		//req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
		//req.Header.Add("User-Agent", " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36")
		//req.Header.Add("authority", "raw.githubusercontent.com")
		//req.Header.Add("cache-control", "max-age=0")
		//req.Header.Add("accept-encoding", "gzip, deflate, br")
		//req.Header.Add("accept-language", "zh-CN,zh;q=0.9")
		//req.Header.Add("sec-fetch-user", "?1")
		//req.Header.Add("upgrade-insecure-requests", "1")
		//
		//client := &http.Client{}
		//if resp, err := client.Do(req); err != nil || resp.StatusCode != http.StatusOK {
		//	fmt.Println(err.Error())
		//	context.String(http.StatusServiceUnavailable, err.Error())
		//	return
		//}

		if resp, err = http.Get(url); err != nil || resp.StatusCode != http.StatusOK {
			//context.Status(http.StatusServiceUnavailable)
			context.String(http.StatusServiceUnavailable, err.Error())
			return
		}

		reader := resp.Body
		contentLength := resp.ContentLength
		contentType := resp.Header.Get("Content-Type")

		extraHeaders := map[string]string{
			"Content-Disposition": `attachment; filename="gopher.png"`,
		}
		context.DataFromReader(http.StatusOK, contentLength, contentType, reader, extraHeaders)
	})
	engine.Run(":8080")
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
		if strings.HasSuffix(path, ".tmpl") {
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

//=============================================================

func NativeRed() {
	fmt.Println(strings.EqualFold("Go", "go"))

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Method, "POST") {
			w.Write([]byte("只支持post请求"))
			return
		}

		w.Write([]byte("hello world"))

		//const _24K = (1 << 10) * 24

		////文件占用内存不能超过32m
		//if err := r.ParseMultipartForm(32 << 20); err != nil {
		//	w.Write([]byte(err.Error()))
		//	return
		//}

		////files := r.MultipartForm.File["file[]"]
		//files := r.MultipartForm.File["file"]
		//fileCount := len(files)
	})
	http.ListenAndServe(":8080", nil)
}

func ginWithNative() {
	engine := gin.Default()
	server := &http.Server{
		Addr:           ":8080",
		Handler:        engine,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, //1m
	}
	server.ListenAndServe()
}

func renderCustomPage() {
	var (
		templateName string
		content      string
		engine       *gin.Engine
	)

	templateName = "test"
	content = `<div id="remoteVideos">{{.title}}</div> <br/>`
	htmlRender := render.HTMLProduction{
		Template: template.Must(template.New(templateName).Parse(content)),
	}

	engine = gin.Default()
	engine.HTMLRender = htmlRender
	engine.GET("/where", func(c *gin.Context) {
		c.Render(200, htmlRender.Instance(templateName, map[string]interface{}{ //gin.H
			"title": "well come gin template render",
		}))
	})

	//重定向
	engine.GET("/info", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/user") //301重定向
		c.Redirect(301, "https://www.google.com/")
	})
	engine.GET("/article", func(c *gin.Context) {
		c.Request.URL.Path = "/user" //修改请求地址
		engine.HandleContext(c)
	})

	engine.Run(":8080")
}

// 更多模板可以参考：https://github.com/gin-contrib/multitemplate
// 将静态资源打包到可执行文件中：https://github.com/jessevdk/go-assets
func demo4() {
	var (
		templateName string
		tmpl         *template.Template
		engine       *gin.Engine
	)

	templateName = "https"
	tmpl = template.Must(template.New(templateName).Parse(`
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

func demoPostData() {
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

func demoPostData2() {
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

// 单文件上传
func post_file() {
	var (
		err  error
		file *multipart.FileHeader
	)

	engine := gin.Default()

	currentDoc := os.Getenv("GOPATH")
	uploadDoc := filepath.Join(currentDoc, "src/upload")

	engine.MaxMultipartMemory = 8 << 20 //8m
	engine.POST("/upload", func(context *gin.Context) {
		if file, err = context.FormFile("file"); err != nil {
			context.String(200, fmt.Sprintf("error:%s", err.Error()))
		}

		if _, err = os.Stat(uploadDoc); os.IsNotExist(err) {
			os.Mkdir(uploadDoc, os.ModeDir)
		}

		if err = context.SaveUploadedFile(file, uploadDoc+"/"+file.Filename); err != nil {
			context.String(200, fmt.Sprintf("error:%s", err.Error()))
		}
		context.String(200, "uploaded!")
	})

	engine.Run(":8080")
}

// 多文件上传
func postFiles() {
	var (
		err           error
		file          *multipart.FileHeader
		form          *multipart.Form
		files         []*multipart.FileHeader
		once          sync.Once
		fileCount     int
		fileLocalPath string
	)

	engine := gin.Default()

	currentDoc := os.Getenv("GOPATH")
	uploadDoc := filepath.Join(currentDoc, "src/upload")

	engine.MaxMultipartMemory = 8 << 20 //8m
	engine.POST("/upload", func(context *gin.Context) {
		datetime := time.Now()

		//多文件上传
		form, _ = context.MultipartForm()
		files = form.File["file"]
		fileCount = len(files)

		if fileCount == 0 {
			context.String(200, "未获取到上传的文件")
		}

		for _, file = range files {
			once.Do(func() {
				fmt.Println("执行了一次")
				if _, err = os.Stat(uploadDoc); os.IsNotExist(err) {
					os.Mkdir(uploadDoc, os.ModeDir)
				}
			})

			fileLocalPath = uploadDoc + "/" + file.Filename
			if err = context.SaveUploadedFile(file, fileLocalPath); err != nil {
				log.Printf("error:%s", err.Error())
			}
		}

		totalTime := time.Now().Sub(datetime).Milliseconds()
		context.String(200, fmt.Sprintf("一共 %d 个文件上传完毕，耗时 %dms !", fileCount, totalTime))
	})

	engine.Run(":8080")
}

// 多文件上传
func postFilesChan() {
	var (
		engine    *gin.Engine
		file      *multipart.FileHeader
		form      *multipart.Form
		files     []*multipart.FileHeader
		once      sync.Once
		fileChan  chan *multipart.FileHeader
		fileCount int
		err       error
	)

	engine = gin.Default()
	engine.MaxMultipartMemory = 8 << 20 //8m

	currentDoc := os.Getenv("GOPATH")
	uploadDoc := filepath.Join(currentDoc, "src/upload")

	engine.POST("/upload", func(context *gin.Context) {
		datetime := time.Now()

		//多文件上传
		form, _ = context.MultipartForm()
		files = form.File["file"]
		fileCount = len(files)

		if fileCount == 0 {
			context.String(200, "未获取到上传的文件")
		}

		fileChan = make(chan *multipart.FileHeader, fileCount)
		//defer close(fileChan)

		for _, file = range files {
			once.Do(func() {
				fmt.Println("执行了一次")
				if _, err = os.Stat(uploadDoc); os.IsNotExist(err) {
					os.Mkdir(uploadDoc, os.ModeDir)
				}
			})

			fileChan <- file //丢入channel中
		}

		//go func() {
		//	defer close(fileChan)
		//	var chanFile *multipart.FileHeader
		//	for {
		//		select {
		//		case chanFile = <-fileChan:
		//		}
		//
		//		go func(fileHeader *multipart.FileHeader) {
		//			fileLocalPath := uploadDoc + "/" + fileHeader.Filename
		//			if err = context.SaveUploadedFile(fileHeader, fileLocalPath); err != nil {
		//				log.Printf("error:%s", err.Error())
		//			}
		//		}(chanFile)
		//	}
		//}()

		go func(cf chan *multipart.FileHeader) {
			defer close(cf)
			var chanFile *multipart.FileHeader
			for {
				select {
				//case chanFile = <-fileChan:
				case chanFile = <-cf:
				}

				go func(fileHeader *multipart.FileHeader) {
					fileLocalPath := uploadDoc + "/" + fileHeader.Filename
					if err = context.SaveUploadedFile(fileHeader, fileLocalPath); err != nil {
						log.Printf("error:%s", err.Error())
					}
				}(chanFile)
			}
		}(fileChan)

		totalTime := time.Now().Sub(datetime).Milliseconds()
		context.String(200, fmt.Sprintf("一共 %d 个文件上传完毕，耗时 %dms !", fileCount, totalTime))
	})

	engine.Run(":8080")
}
