package anticaptcha

import (
	"github.com/go-errors/errors"
	"strconv"
)

type ErrAntiCaptcha struct {
	Id      int
	Code    string
	Message string
}

func (self *ErrAntiCaptcha) Error() string {
	return "code(" + strconv.Itoa(self.Id) + ":" + self.Code + ") -  " + self.Message
}

var ErrCaptchaInProcess = errors.New("captcha in processing")
var ErrAttemptsExceed = errors.New("captcha attempts exceed")
var ErrCheckTimeout = errors.New("captcha check timeout")
