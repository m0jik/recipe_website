package main

import (
  "net/http"

  "github.com/gin-gonic/gin"
)

func main() {
  r := gin.Default()
  r.GET("/resource", gin.BasicAuth(gin.Accounts{
        "admin": "secret",
    }), func(c *gin.Context) {

    c.JSON(http.StatusOK, gin.H{
      "data": "resource data",
    })
  })
  r.Run() // Listen and serve on 0.0.0.0:8080 (for Windows "localhost:8080")
}