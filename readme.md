Anticaptcha Api

Install 
-----

```go get github.com/sintanial/go-anticaptcha ```


Docs 
-----

```https://godoc.org/github.com/sintanial/go-anticaptcha```


Usage 
-----

```golang
    ac := anticaptcha.New("YOUR API KEY")
    data, err := ioutil.ReadFile("./captcha.jpeg")
    if err != nil {
        panic(err)
    }

    res, err := ac.ImageToTextResolver().Solution(data, nil)
    if err != nil {
        panic(err)
    }

    fmt.Println(res)
```

More docs can find in source code ;)