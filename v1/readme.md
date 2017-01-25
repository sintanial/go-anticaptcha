Anticaptcha Api

Usage
-----

```golang
    ac := New("YOUR API KEY HERE")

	answer, err := ac.ResolveBytes([]byte("IMAGE BINARY DATA")), nil)
	if err != nil {
		panic(err)
	}
	
	fmt.Println(answer)
```