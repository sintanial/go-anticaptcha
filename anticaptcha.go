package anticaptcha

import (
	"github.com/go-errors/errors"
	"mime/multipart"
	"bytes"
	"net/http"
	"io/ioutil"
	"io"
	"strings"
	"time"
	"strconv"
)

var ErrWrongUserKey = errors.New("anti-captcha: wrong user key")
var ErrKeyDoesNotExist = errors.New("anti-captcha: key does not exist")
var ErrZeroBalance = errors.New("anti-captcha: zero balance")
var ErrNoSlotAvailable = errors.New("anti-captcha: no slot available")
var ErrZeroCaptchaFilesize = errors.New("anti-captcha: zero captcha filesize")
var ErrImageTypeNotSupported = errors.New("anti-captcha: image type not supported")
var ErrIpNowAllowed = errors.New("anti-captcha: ip not allowed")
var ErrInvalidResponse = errors.New("anti-captcha: invalid response")

var ErrWrongIdFormat = errors.New("anti-captcha: wrong id format")
var ErrNoSuchCapchaId = errors.New("anti-captcha: no such captcha id")
var ErrCaptchaUnsolvable = errors.New("anti-captcha: captcha unsolvable")

var ErrCaptchaNotReady = errors.New("anti-captcha: captcha not ready")

const CaptchaTypeRecaptcha2 = "recaptcha2"
const CaptchaTypeRecaptcha2_44 = "recaptcha2_44"
const CaptchaTypeRecaptcha2_24 = "recaptcha2_24"
const CaptchaTypeAudio = "audio"

const NumericNoNumbers = 1
const NumericOnlyNumbers = 2

var errorList = map[string]error{
	"ERROR_WRONG_USER_KEY" : ErrWrongUserKey,
	"ERROR_KEY_DOES_NOT_EXIST" : ErrKeyDoesNotExist,
	"ERROR_ZERO_BALANCE" : ErrZeroBalance,
	"ERROR_NO_SLOT_AVAILABLE" : ErrNoSlotAvailable,
	"ERROR_ZERO_CAPTCHA_FILESIZE" : ErrZeroCaptchaFilesize,
	"ERROR_IMAGE_TYPE_NOT_SUPPORTED" : ErrImageTypeNotSupported,
	"ERROR_IP_NOT_ALLOWED" : ErrIpNowAllowed,
	"ERROR_WRONG_ID_FORMAT" : ErrWrongIdFormat,
	"ERROR_NO_SUCH_CAPCHA_ID" : ErrNoSuchCapchaId,
	"ERROR_CAPTCHA_UNSOLVABLE" : ErrCaptchaUnsolvable,
	"CAPCHA_NOT_READY" : ErrCaptchaNotReady,
}

type Options struct {
	Phrase     bool
	Regsense   bool
	Numeric    int
	Calc       bool
	MinLen     int
	MaxLen     int
	IsRussian  bool
	Type       string
	Comment    string
	AllowEmpty bool
}

type Anticaptcha struct {
	Key    string
	Client *http.Client
}

func New(key string) *Anticaptcha {
	return &Anticaptcha{Key: key}
}

func (self *Anticaptcha) getClient() *http.Client {
	if self.Client == nil {
		return http.DefaultClient
	}

	return self.Client
}

func (self *Anticaptcha) ResolveCaptcha(captcha []byte, isBase64 bool, opts *Options) (string, error) {
	captchaId, err := self.LoadCaptcha(captcha, isBase64, opts)
	if err != nil {
		return "", err
	}

	answerch := make(chan string)
	errch := make(chan error)

	var timer *time.Timer
	attempts := 0
	timer = time.AfterFunc(5 * time.Second, func() {
		attempts++

		answer, err := self.GetAnswer(captchaId)
		if err != nil {
			if err == ErrCaptchaNotReady {

				if attempts > 300 / 5 {
					errch <- ErrCaptchaUnsolvable
					return
				}

				timer.Reset(5 * time.Second)
				return
			}

			errch <- err
			return
		}

		answerch <- answer
	})

	select {
	case err := <-errch:
		return "", err
	case res := <-answerch:
		return res, nil
	}
}

func (self *Anticaptcha) ResolveBase64(captcha []byte, opts *Options) (string, error) {
	return self.ResolveCaptcha(captcha, true, opts)
}

func (self *Anticaptcha) ResolveBytes(captcha []byte, opts *Options) (string, error) {
	return self.ResolveCaptcha(captcha, false, opts)
}

func (self *Anticaptcha) ResolveReader(r io.Reader, opts *Options) (string, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	return self.ResolveBytes(data, opts)
}

func (self *Anticaptcha) writeOptions(data *multipart.Writer, opts *Options) error {
	if opts == nil {
		return nil
	}

	if opts.Phrase {
		if err := data.WriteField("phrase", btoia(opts.Phrase)); err != nil {
			return err
		}
	}

	if opts.Regsense {
		if err := data.WriteField("regsense", btoia(opts.Regsense)); err != nil {
			return err
		}
	}

	if opts.Numeric > 0 {
		if err := data.WriteField("numeric", strconv.Itoa(opts.Numeric)); err != nil {
			return err
		}
	}

	if opts.Calc {
		if err := data.WriteField("calc", btoia(opts.Calc)); err != nil {
			return err
		}
	}

	if opts.MinLen >= 1 && opts.MinLen <= 20 {
		if err := data.WriteField("min_len", strconv.Itoa(opts.MinLen)); err != nil {
			return err
		}
	}

	if opts.MaxLen >= 1 && opts.MaxLen <= 20 {
		if err := data.WriteField("max_len", strconv.Itoa(opts.MaxLen)); err != nil {
			return err
		}
	}

	if opts.IsRussian {
		if err := data.WriteField("is_russian", btoia(opts.IsRussian)); err != nil {
			return err
		}
	}

	if opts.Type != "" {
		if err := data.WriteField("type", opts.Type); err != nil {
			return err
		}
	}

	if opts.Comment != "" {
		if err := data.WriteField("comment", opts.Comment); err != nil {
			return err
		}
	}

	if opts.AllowEmpty {
		if err := data.WriteField("allow_empty", btoia(opts.AllowEmpty)); err != nil {
			return err
		}
	}

	return nil
}

func (self *Anticaptcha) LoadCaptcha(captcha []byte, isBase64 bool, opts *Options) (string, error) {
	reqbody := &bytes.Buffer{}
	formwriter := multipart.NewWriter(reqbody)

	if err := formwriter.WriteField("key", self.Key); err != nil {
		return "", err
	}

	if !isBase64 {
		if err := formwriter.WriteField("method", "post"); err != nil {
			return "", err
		}

		fw, err := formwriter.CreateFormFile("file", "captcha")
		if err != nil {
			return "", err
		}

		if _, err := fw.Write(captcha); err != nil {
			return "", err
		}
	} else {
		if err := formwriter.WriteField("method", "base64"); err != nil {
			return "", err
		}

		if err := formwriter.WriteField("body", string(captcha)); err != nil {
			return "", err
		}
	}

	if err := self.writeOptions(formwriter, opts); err != nil {
		return "", err
	}

	if err := formwriter.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "http://anti-captcha.com/in.php", reqbody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", formwriter.FormDataContentType())

	resp, err := self.getClient().Do(req)
	if err != nil {
		return "", err
	}

	respbody, err := readAllStr(resp.Body)
	if err != nil {
		return "", err
	}

	if err, ok := errorList[respbody]; ok {
		return "", err
	}

	return parseOkResponse(respbody);
}

func (self *Anticaptcha) LoadBase64(captcha []byte, opts *Options) (string, error) {
	return self.LoadCaptcha(captcha, true, opts)
}

func (self *Anticaptcha) LoadBytes(captcha []byte, opts *Options) (string, error) {
	return self.LoadCaptcha(captcha, false, opts)
}

func (self *Anticaptcha) LoadReader(r io.Reader, opts *Options) (string, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	return self.LoadBytes(data, opts)
}

func (self *Anticaptcha) GetAnswer(captchaId string) (string, error) {
	resp, err := self.getClient().Get("http://anti-captcha.com/res.php?key=" + self.Key + "&action=get&id=" + captchaId)
	if err != nil {
		return "", err
	}

	respbody, err := readAllStr(resp.Body)
	if err != nil {
		return "", err
	}

	if err, ok := errorList[respbody]; ok {
		return "", err
	}

	return parseOkResponse(respbody)
}

func parseOkResponse(resp string) (string, error) {
	if !strings.Contains(resp, "OK|") {
		return "", ErrInvalidResponse
	}

	data := strings.Split(resp, "|")
	if len(data) < 2 {
		return "", ErrInvalidResponse
	}

	return data[1], nil
}

func btoia(b bool) string {
	if b {
		return "1"
	}

	return "0"
}

func readAllStr(r io.Reader) (string, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
}