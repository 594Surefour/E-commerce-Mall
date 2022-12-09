# Go电商项目

## [1]项目简介

架构

本电商项目采用mvc设计模式，及Model-View-Controller设计模式，有五大模块：

1. 用户模块user
2. 商品分类模块category
3. 商品模块product
4. 订单模块order
5. 购物车模块cart

文件夹类别：

1. api ，包括controller和router路由，向客户端提供api接口。
2. config，系统配置文件和配置类
3. docs，swagger文档配置类和配置文件
4. domain，数据模型entity、数据逻辑repository、和业务逻辑service
5. utils，系统工具类，jwt、中间件、分页等



## [2]初始化项目

(2-1)安装gorm库

```
go get gorm.io/gorm
go get gorm.io/driver/mysql
```

(2-2)创建mysql数据库

```sql
create database go_database
```



## [3]用户

在项目根目录下面创建domain目录，在该目录下面创建user目录

#### (3-1)实体类

在user目录下面创建entity.go文件内如如下：



#### (3-2)创建错误处理类

在user目录下面创建`user.go`文件，内容如下：

#### (3-3)用户密码处理

##### (3-3-1)创建密码加密工具类

安装加密库bcrypt

```
go get golang.org/x/crypto/bcrypt
```

创建密码加密工具类

在项目根目录下面创建utils文件夹，在该文件夹下面创建hash文件夹，在hash文件夹下面创建hash.go文件，内如下：

```go
package hash

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// 随机字符串
const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// 使用当前时间创建seed
var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

// 创建salt
func CreateSalt() string {
	b := make([]byte, bcrypt.MaxCost)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// 使用bcrypt算法返回hash后密码
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// 检查密码是否相等
func CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
```

##### (3-3-2)保存密码之前的hooks

保存用户之前回调，如果密码没有被加密加密密码和salt，在user目录下面创建hooks.go文件，内容如下：

```go
package user

import (
	"shopping/utils/hash"

	"gorm.io/gorm"
)

// 保存用户之前回调，如果密码没有被加密加密密码和salt
func (u *User) BeforeSave(tx *gorm.DB) (err error) {

	if u.Salt == "" {
		// 为salt创建一个随机字符串
		salt := hash.CreateSalt()
		// 创建hash加密密码
		hashPassword, err := hash.HashPassword(u.Password + salt)
		if err != nil {
			return nil
		}
		u.Password = hashPassword
		u.Salt = salt
	}

	return
}
```

#### (3-4)创建用户名密码验证工具类

在user目录下面创建`validation.go`文件，内容如下：

```go
package user

import "regexp"

// 用户名正则表达式，最小8个字符，最大 30个字符，用户名字母打头
var usernameRegex = regexp.MustCompile("^[A-Za-z][A-Za-z0-9_]{7,29}$")

// 密码正则表达式，最小8个字符，至少一个字符一个数字
var passwordRegex = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{7,29}$`)

func ValidateUserName(name string) bool {
	return usernameRegex.MatchString(name)
}

func ValidatePassword(password string) bool {
	return passwordRegex.MatchString(password)

}
```

#### (3-5)用户dao层

在user目录下面创建`repository.go`文件：



#### (3-6)用户service层





## [4]商品分类

#### (4-1)实体类

在domain目录下面创建category目录，在category目录下面创建entity.go文件

#### (4-2)错误类

#### (4-3)商品分类dao层

#### (4-4)商品分类service层



## [5]分页工具类

#### 安装gin库

```
go get github.com/gin-gonic/gin
```

#### 创建分页工具类

在`utils`目录下面创建`pagination`目录，在该目录下面创建`pages.go`文件，内容如下：

```go
package pagination

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

//TODO: refactor methods
var (
	// 默认页数
	DefaultPageSize = 100
	// 最大页数
	MaxPageSize = 1000
	// 查询参数名称
	PageVar = "page"
	// 页数查询参数名称
	PageSizeVar = "pageSize"
)

// 分页结构体
type Pages struct {
	Page       int         `json:"page"`
	PageSize   int         `json:"pageSize"`
	PageCount  int         `json:"pageCount"`
	TotalCount int         `json:"totalCount"`
	Items      interface{} `json:"items"`
}

// 实例化分页结构体
func New(page, pageSize, total int) *Pages {
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	pageCount := -1
	if total >= 0 {
		pageCount = (total + pageSize - 1) / pageSize
		if page > pageCount {
			page = pageCount
		}

	}
	if page <= 0 {
		page = 1
	}

	return &Pages{
		Page:       page,
		PageSize:   pageSize,
		TotalCount: total,
		PageCount:  pageCount,
	}
}

// 根据http请求实例化分页结构体
func NewFromRequest(req *http.Request, count int) *Pages {
	page := ParseInt(req.URL.Query().Get(PageVar), 1)
	pageSize := ParseInt(req.URL.Query().Get(PageSizeVar), DefaultPageSize)
	return New(page, pageSize, count)
}

// 根据gin请求实例化分页结构体
func NewFromGinRequest(g *gin.Context, count int) *Pages {
	page := ParseInt(g.Query(PageVar), 1)
	pageSize := ParseInt(g.Query(PageSizeVar), DefaultPageSize)
	return New(page, pageSize, count)
}

// 类型转换
func ParseInt(value string, defaultValue int) int {
	if value == "" {
		return defaultValue
	}
	if result, err := strconv.Atoi(value); err == nil {
		return result
	}
	return defaultValue
}

// offset
func (p *Pages) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// limit
func (p *Pages) Limit() int {
	return p.PageSize
}
```



## [6]解析csv文件工具类



## [7]商品模型

#### (7-1)实体类

#### (7-2)错误类

#### (7-3)保存商品之前生成商品sku

安装uuid库

```
go get github.com/google/uuid
```

在product目录下面创建`hooks.go`文件，内容如下：

```go
package product

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// 保存商品之前生成商品sku
func (p *Product) BeforeSave(tx *gorm.DB) (err error) {
	p.SKU = uuid.New().String()
	return
}
```

#### (7-4)商品dao层

#### (7-5)商品service层





## [8]购物车

#### (8-1)实体类



#### (8-2)自定义错误类



#### (8-3)购物车dao层



#### (8-4)购物车service层





## [9]订单

#### (9-1)实体类



#### (9-2)自定义错误



#### (9-3)hooks



#### (9-4)订单dao层



#### (9-5)订单service层



## [10]api辅助类

在utils目录下面创建`api_helper`文件夹。

#### (10-1)创建types

在`api_helper`文件夹下面创建`types.go`文件，内容如下：

```go
package api_helper

import "errors"

// 响应结构体
type Response struct {
	Message string `json:"message"`
}

// 响应错误结构体
type ErrorResponse struct {
	Message string `json:"errorMessage"`
}

// 自定义错误
var (
	ErrInvalidBody = errors.New("请检查你的请求体")
)
```

#### (10-2)用户查询辅助类

在`api_helper`文件夹下面创建`query_helper.go`文件，内容如下：

```go
package api_helper

import (
	"shopping/utils/pagination"

	"github.com/gin-gonic/gin"
)

var userIdText = "userId"

// 从context获得用户id
func GetUserId(g *gin.Context) uint {
	return uint(pagination.ParseInt(g.GetString(userIdText), -1))
}
```

#### (10-3)错误处理辅助类

在`api_helper`文件夹下面创建`error_handler.go`文件，内容如下：

```go
package api_helper

import (
	"net/http"
	"github.com/gin-gonic/gin"
)

// 错误处理
func HandleError(g *gin.Context, err error) {

	g.JSON(
		http.StatusBadRequest, ErrorResponse{
			Message: err.Error(),
		})
	g.Abort()
	return
}
```



## [11]系统配置类

#### (11-1)安装viper包

```
go get github.com/spf13/viper
```

#### (11-2)创建系统配置类

在项目根目录下面创建`config`目录，在该目录下面创建`config.go`文件，内容如下：

```go
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

var cfgReader *configReader

type (
	Configuration struct {
		DatabaseSettings
		JwtSettings
	}
	// 数据库配置
	DatabaseSettings struct {
		DatabaseURI  string
		DatabaseName string
		Username     string
		Password     string
	}
	// jwt配置
	JwtSettings struct {
		SecretKey string
	}
	// reader
	configReader struct {
		configFile string
		v          *viper.Viper
	}
)

// 获得所有配置
func GetAllConfigValues(configFile string) (configuration *Configuration, err error) {
	newConfigReader(configFile)
	if err = cfgReader.v.ReadInConfig(); err != nil {
		fmt.Printf("配置文件读取失败 : %s", err)
		return nil, err
	}

	err = cfgReader.v.Unmarshal(&configuration)
	if err != nil {
		fmt.Printf("解析配置文件到结构体失败 : %s", err)
		return nil, err
	}

	return configuration, err
}

// 实例化configReader
func newConfigReader(configFile string) {
	v := viper.GetViper()
	v.SetConfigType("yaml")
	v.SetConfigFile(configFile)
	cfgReader = &configReader{
		configFile: configFile,
		v:          v,
	}
}
```

#### (11-3)创建配置文件

在`config`目录下面创建`config.yaml`文件，内容如下：

```yaml
Env: "dev"

DatabaseSettings:
  DatabaseURI: "root:123456@tcp(127.0.0.1:3306)/go_database?parseTime=True&loc=Local"
  DatabaseName: "go_database"
  Username: "root"
  Password: "123456"


JwtSettings:
  SecretKey: "golang-tech-stack.com"
```



## [12]jwt工具类

#### (12-1)安装jwt包

```
go get github.com/dgrijalva/jwt-go
```

#### (12-2)创建jwt工具类

在`utils`目录下面创建`jwt`文件夹，在该文件夹下面创建`jwt_helper.go`文件，内容如下：

```go
package jwt

import (
	"encoding/json"
	"log"

	"github.com/dgrijalva/jwt-go"
)

// 解码token
type DecodedToken struct {
	Iat      int    `json:"iat"`
	UserId   string `json:"userId"`
	Username string `json:"username"`
	Iss      string `json:"iss"`
	IsAdmin  bool   `json:"isAdmin"`
}

// 生成token
func GenerateToken(claims *jwt.Token, secret string) (token string) {
	hmacSecretString := secret
	hmacSecret := []byte(hmacSecretString)
	token, _ = claims.SignedString(hmacSecret)

	return
}

// 验证token
func VerifyToken(token string, secret string) *DecodedToken {
	hmacSecretString := secret
	hmacSecret := []byte(hmacSecretString)

	decoded, err := jwt.Parse(
		token, func(token *jwt.Token) (interface{}, error) {
			return hmacSecret, nil
		})

	if err != nil {
		return nil
	}

	if !decoded.Valid {
		return nil
	}

	decodedClaims := decoded.Claims.(jwt.MapClaims)

	var decodedToken DecodedToken
	jsonString, _ := json.Marshal(decodedClaims)
	jsonErr := json.Unmarshal(jsonString, &decodedToken)
	if jsonErr != nil {
		log.Print(jsonErr)
	}

	return &decodedToken
}
```



## [13]controller层





## [14]中间件



## [15]数据库工具类





## [16]路由



## [17]关闭gin服务器工具类



## [18]swagger配置

#### (18-1)安装swag包

```
go install github.com/swaggo/swag/cmd/swag@v1.6.7
```

#### (18-2)生成配置文件

在项目根目录下面创建docs目录，在终端执行如下命令

```
swag init
```

执行后会在docs目录下面生成swagger配置文件。

## [19]主启动类和测试类

