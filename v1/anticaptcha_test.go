package v1anticaptcha

import (
	"encoding/base64"
	"io/ioutil"
	"testing"
)

var TEST_KEY = ""

func TestAnticaptcha_ResolveBytes(t *testing.T) {
	ac := New(TEST_KEY)

	data, err := ioutil.ReadFile("./../testdata/captcha.jpeg")
	if err != nil {
		t.Fatal(err.Error())
	}

	res, err := ac.ResolveBytes(data, nil)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(res) != "y72bxc" {
		t.Fatal("failed to resolve captcha")
	}
}

func TestAnticaptcha_ResolveBase64(t *testing.T) {
	ac := New(TEST_KEY)

	data, err := ioutil.ReadFile("./../testdata/captcha.jpeg")
	if err != nil {
		t.Fatal(err.Error())
	}

	res, err := ac.ResolveBase64([]byte(base64.StdEncoding.EncodeToString(data)), nil)
	if err != nil {
		t.Fatal(err.Error())
	}

	if string(res) != "y72bxc" {
		t.Fatal("failed to resolve captcha")
	}
}
