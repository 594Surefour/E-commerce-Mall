# Go电商项目

## [1]项目简介



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





## [3]创建用户模型和错误处理

创建目录

在项目根目录下面创建domain目录，在该目录下面创建user目录

(3-1)创建用户模型

在user目录下面创建entity.go文件内如如下：



(3-2)创建错误处理类

在user目录下面创建`user.go`文件，内容如下：







## [4]用户密码

#### (4-1)创建密码加密工具类

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

#### (4-2)保存密码之前的hooks

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

#### (4-3)创建用户名密码验证工具类

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



## [5]用户逻辑

#### (5-1)dao层

在user目录下面创建`repository.go`文件：



#### (5-2)service层



## [6]商品分类



## [7]分页工具



## [8]解析csv文件工具类



## [9]商品模型





## [10]购物车



## [11]订单



## [12]api辅助类



## [13]系统配置类



## [14]jwt工具类





## [15]controller层





## [16]中间件



## [17]数据库工具类





## [18]路由



## [19]关闭gin服务器工具类



## [20]swagger配置



## [21]主启动类和测试类

